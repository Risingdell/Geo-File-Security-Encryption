import os

import pytest
from fastapi.testclient import TestClient

from higtlc.container import Location, open_file, seal_file
from higtlc.keys import Identity
from higtlc.lta_client import LTAClient, LTAError, RelayClient
from higtlc.lta_server import create_app
from higtlc.policy import circle_zone, make_policy

SITE = (12.872323, 74.940850)
T0 = 1_800_000_000


@pytest.fixture
def env(tmp_path):
    t = {"now": T0}
    app = create_app(tmp_path / "srv", clock=lambda: t["now"])
    http = TestClient(app)
    alice, bob, eve = Identity.generate("alice"), Identity.generate("bob"), Identity.generate("eve")
    src = tmp_path / "plan.docx"
    src.write_bytes(os.urandom(150_000))
    sealed = tmp_path / "plan.docx.hig"
    policy = make_policy(recipient_sign_pk=bob.public().sign_pk_b64, zone=circle_zone(*SITE, 200),
                         not_before=T0, not_after=T0 + 3600, max_accuracy_m=100)
    seal_file(src, sealed, sender=alice, recipient=bob.public(), policy=policy,
              lta=LTAClient("http://testserver", http=http))
    return type("Env", (), dict(tmp=tmp_path, http=http, t=t, alice=alice, bob=bob, eve=eve,
                                src=src, sealed=sealed,
                                lta=LTAClient("http://testserver", http=http),
                                relay=RelayClient("http://testserver", http=http)))


def test_transfer_and_open(env, monkeypatch):
    monkeypatch.setattr("time.time", lambda: env.t["now"])  # inbox auth timestamp
    file_id = env.relay.upload(env.sealed)
    [item] = env.relay.inbox(env.bob)
    assert item["id"] == file_id and item["filename"] == "plan.docx"
    got = env.tmp / "got.hig"
    env.relay.download(file_id, got)
    assert got.read_bytes() == env.sealed.read_bytes()
    out = env.tmp / "out.docx"
    open_file(got, out, recipient=env.bob, location=Location(*SITE, 75), lta=env.lta,
              expected_sender=env.alice.public())
    assert out.read_bytes() == env.src.read_bytes()
    env.relay.delete(env.bob, file_id)
    assert env.relay.inbox(env.bob) == []


def test_inbox_is_private(env, monkeypatch):
    monkeypatch.setattr("time.time", lambda: env.t["now"])
    file_id = env.relay.upload(env.sealed)
    assert env.relay.inbox(env.eve) == []
    with pytest.raises(LTAError) as e:
        env.relay.delete(env.eve, file_id)
    assert e.value.status == 403


def test_inbox_rejects_forged_or_stale_auth(env, monkeypatch):
    monkeypatch.setattr("time.time", lambda: env.t["now"] - 3600)
    with pytest.raises(LTAError, match="stale"):
        env.relay.inbox(env.bob)
    monkeypatch.setattr("time.time", lambda: env.t["now"])
    params = env.relay._auth(env.eve)
    params["recipient"] = env.bob.public().sign_pk_b64
    r = env.http.get("/v1/relay/inbox", params=params)
    assert r.status_code == 401


def test_relay_rejects_junk_and_tampered_files(env):
    r = env.http.post("/v1/relay/files", content=b"hello")
    assert r.status_code == 400
    raw = env.sealed.read_bytes().replace(b'"radius_m":200', b'"radius_m":900', 1)
    r = env.http.post("/v1/relay/files", content=raw)
    assert r.status_code == 400 and "signature" in r.text


def test_relay_rejects_bad_ids(env):
    assert env.http.get("/v1/relay/files/..%2Flta_key").status_code in (400, 404)
    assert env.http.get("/v1/relay/files/deadbeef").status_code == 404
