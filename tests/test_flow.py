import json
import os

import pytest
from fastapi.testclient import TestClient

from higtlc.container import Location, OpenError, open_file, read_envelope, seal_file
from higtlc.keys import Identity, load_identity, load_public, save_identity, save_public
from higtlc.lta_client import LTAClient, LTAError
from higtlc.lta_server import MAX_FAILURES_PER_HOUR, create_app
from higtlc.policy import PolicyError, circle_zone, make_policy, polygon_zone

SITE = (28.612900, 77.229500)            # target site
NEARBY = Location(28.612950, 77.229550, 8)  # ~7 m away
FAR = Location(28.700000, 77.100000, 8)     # ~16 km away
T0 = 1_800_000_000


class Clock:
    def __init__(self, t): self.t = t
    def __call__(self): return self.t


@pytest.fixture
def env(tmp_path):
    clock = Clock(T0)
    app = create_app(tmp_path / "lta", clock=clock, dev_attestation=True)
    lta = LTAClient("http://testserver", http=TestClient(app))
    alice, bob, mallory = Identity.generate("alice"), Identity.generate("bob"), Identity.generate("mallory")
    src = tmp_path / "secret.pdf"
    src.write_bytes(os.urandom(200_000) + b"THE END")  # spans several 64 KiB chunks
    return type("Env", (), dict(tmp=tmp_path, clock=clock, app=app, lta=lta,
                                alice=alice, bob=bob, mallory=mallory, src=src))


def seal(env, **policy_kw):
    kw = dict(recipient_sign_pk=env.bob.public().sign_pk_b64, zone=circle_zone(*SITE, 50),
              not_before=T0, not_after=T0 + 3600)
    kw.update(policy_kw)
    out = env.tmp / "secret.pdf.hig"
    seal_file(env.src, out, sender=env.alice, recipient=env.bob.public(), policy=make_policy(**kw), lta=env.lta)
    return out


def do_open(env, sealed, who=None, loc=NEARBY, **kw):
    out = env.tmp / "opened.pdf"
    open_file(sealed, out, recipient=who or env.bob, location=loc, lta=env.lta,
              expected_sender=env.alice.public(), **kw)
    return out.read_bytes()


def test_happy_path(env):
    assert do_open(env, seal(env)) == env.src.read_bytes()


def test_polygon_zone(env):
    lat, lon = SITE
    square = polygon_zone([(lat - .001, lon - .001), (lat - .001, lon + .001),
                           (lat + .001, lon + .001), (lat + .001, lon - .001)])
    sealed = seal(env, zone=square)
    assert do_open(env, sealed) == env.src.read_bytes()
    with pytest.raises(LTAError, match="outside"):
        do_open(env, sealed, loc=FAR)


def test_empty_file(env):
    env.src.write_bytes(b"")
    assert do_open(env, seal(env)) == b""


def test_ciphertext_contains_no_plaintext(env):
    assert b"THE END" not in seal(env).read_bytes()


def test_wrong_location_denied(env):
    with pytest.raises(LTAError, match="outside the permitted zone"):
        do_open(env, seal(env), loc=FAR)
    assert not (env.tmp / "opened.pdf").exists()


def test_poor_gps_accuracy_denied(env):
    with pytest.raises(LTAError, match="accuracy"):
        do_open(env, seal(env), loc=Location(*SITE, 200))


def test_before_window_denied(env):
    sealed = seal(env, not_before=T0 + 600, not_after=T0 + 3600)
    with pytest.raises(LTAError, match="not open yet"):
        do_open(env, sealed)
    env.clock.t = T0 + 700
    assert do_open(env, sealed) == env.src.read_bytes()


def test_expiry_destroys_key_share_permanently(env):
    sealed = seal(env)
    env.clock.t = T0 + 3601
    with pytest.raises(LTAError, match="unknown or expired ticket"):
        do_open(env, sealed)
    # Even rolling the LTA clock back cannot help: K_G was deleted.
    env.clock.t = T0 + 10
    with pytest.raises(LTAError, match="unknown or expired ticket"):
        do_open(env, sealed)
    rows = env.app.state.store.q("SELECT COUNT(*) FROM tickets")
    assert rows[0][0] == 0


def test_wrong_recipient_cannot_open(env):
    with pytest.raises(OpenError, match="different recipient"):
        do_open(env, seal(env), who=env.mallory)


def test_stolen_ticket_evidence_signed_by_attacker_denied(env):
    """Mallory has the file and is at the site, but isn't the recipient."""
    sealed = seal(env)
    header, _, _ = read_envelope(sealed)
    nonce = env.lta.nonce(header["ticket"])
    body = {"ticket": header["ticket"], "nonce": nonce, "lat": NEARBY.lat, "lon": NEARBY.lon,
            "accuracy_m": NEARBY.accuracy_m, "reply_pk": "AAAA", "beacon_sig": None, "attestation": None}
    from higtlc.util import evidence_sig_message
    sig = env.mallory.sign_sk.sign(evidence_sig_message(body)).signature
    with pytest.raises(LTAError, match="not signed by the policy's recipient"):
        env.lta.release(body, sig)


def test_nonce_cannot_be_replayed(env):
    sealed = seal(env)
    header, _, _ = read_envelope(sealed)
    captured = {}
    real_release = env.lta.release

    def spy(body, sig):
        captured.update(body=body, sig=sig)
        return real_release(body, sig)

    env.lta.release = spy
    do_open(env, sealed)
    env.lta.release = real_release
    with pytest.raises(LTAError, match="nonce"):
        env.lta.release(captured["body"], captured["sig"])


def test_tampered_policy_in_header_rejected(env):
    sealed = seal(env)
    raw = sealed.read_bytes()
    tampered = raw.replace(b'"radius_m":50.0', b'"radius_m":99999') if b'"radius_m":50.0' in raw \
        else raw.replace(b'"radius_m":50', b'"radius_m":99')
    assert tampered != raw
    sealed.write_bytes(tampered)
    with pytest.raises(OpenError, match="signature invalid"):
        do_open(env, sealed)


def test_tampered_ciphertext_rejected(env):
    sealed = seal(env)
    raw = bytearray(sealed.read_bytes())
    raw[-100] ^= 0x01
    sealed.write_bytes(bytes(raw))
    with pytest.raises(OpenError, match="authentication failed"):
        do_open(env, sealed)
    assert not (env.tmp / "opened.pdf").exists()


def test_forged_sender_rejected(env):
    sealed = seal(env)
    with pytest.raises(OpenError, match="expected sender"):
        open_file(sealed, env.tmp / "x", recipient=env.bob, location=NEARBY, lta=env.lta,
                  expected_sender=env.mallory.public())


def test_beacon_required(env):
    beacon = Identity.generate("site-beacon")
    sealed = seal(env, beacon_pk=beacon.public().sign_pk_b64)
    with pytest.raises(LTAError, match="beacon"):
        do_open(env, sealed)
    with pytest.raises(LTAError, match="beacon"):
        do_open(env, sealed, beacon=Identity.generate("fake-beacon"))
    assert do_open(env, sealed, beacon=beacon) == env.src.read_bytes()


def test_attestation_required(env):
    sealed = seal(env, require_attestation=True)
    with pytest.raises(LTAError, match="attestation"):
        do_open(env, sealed)
    assert do_open(env, sealed, dev_attestation=True) == env.src.read_bytes()


def test_rate_limit(env):
    sealed = seal(env, not_after=T0 + 7200)
    for _ in range(MAX_FAILURES_PER_HOUR):
        with pytest.raises(LTAError, match="outside"):
            do_open(env, sealed, loc=FAR)
    with pytest.raises(LTAError) as e:
        do_open(env, sealed)  # correct location, but locked out
    assert e.value.status == 429
    env.clock.t = T0 + 3601  # failures age out after an hour
    assert do_open(env, sealed) == env.src.read_bytes()


def test_lta_alone_cannot_decrypt(env):
    """A fully compromised LTA has K_G but not K_R, so it still cannot decrypt."""
    from nacl.public import PrivateKey, SealedBox
    from higtlc.container import _decrypt_stream
    from higtlc.util import b64d, derive_file_key
    sealed = seal(env)
    header, _, offset = read_envelope(sealed)
    lta_sk = PrivateKey(b64d(json.loads((env.tmp / "lta" / "lta_key.json").read_text())["enc_sk"]))
    sealed_kg = env.app.state.store.q("SELECT sealed_kg FROM tickets")[0][0]
    k_g = SealedBox(lta_sk).decrypt(sealed_kg)
    guess = derive_file_key(os.urandom(32), k_g, header["policy"])
    with pytest.raises(OpenError, match="authentication failed"):
        _decrypt_stream(sealed, offset, env.tmp / "stolen.pdf", header, guess)


def test_audit_log_records_attempts(env):
    sealed = seal(env)
    with pytest.raises(LTAError):
        do_open(env, sealed, loc=FAR)
    do_open(env, sealed)
    rows = env.app.state.store.q("SELECT action, outcome FROM audit ORDER BY id")
    assert rows == [("register", "ok"), ("release", "denied"), ("release", "granted")]


def test_invalid_policies():
    with pytest.raises(PolicyError):
        make_policy(recipient_sign_pk="x", zone=circle_zone(0, 0, 50), not_before=10, not_after=5)
    with pytest.raises(PolicyError):
        make_policy(recipient_sign_pk="x", zone=circle_zone(95, 0, 50), not_before=0, not_after=5)


def test_identity_file_roundtrip(tmp_path):
    ident = Identity.generate("bob")
    save_identity(ident, tmp_path / "bob.id", "correct horse")
    save_public(ident.public(), tmp_path / "bob.pub")
    assert bytes(load_identity(tmp_path / "bob.id", "correct horse").enc_sk) == bytes(ident.enc_sk)
    assert load_public(tmp_path / "bob.pub").fingerprint == ident.public().fingerprint
    with pytest.raises(ValueError, match="passphrase"):
        load_identity(tmp_path / "bob.id", "wrong")
