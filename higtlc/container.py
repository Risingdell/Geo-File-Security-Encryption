"""Sealing and opening .hig files.

File layout:
    MAGIC (8 bytes) | envelope length (u32 BE) | envelope JSON | ciphertext stream

Envelope = {"header": {...}, "sig": b64}, signed by the sender's Ed25519 key.
Ciphertext = libsodium secretstream (XChaCha20-Poly1305) under K_file, 64 KiB chunks.
"""
import hashlib
import json
import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from nacl import bindings as nb
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, SealedBox
from nacl.signing import VerifyKey

from .keys import Identity, PublicIdentity
from .lta_client import LTAClient
from .util import (b64d, b64e, beacon_sig_message, canon, derive_file_key,
                   evidence_sig_message, header_sig_message, sha256)

MAGIC = b"HIGTLC\x01\n"
CHUNK = 64 * 1024
ABYTES = nb.crypto_secretstream_xchacha20poly1305_ABYTES
TAG_MESSAGE = nb.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = nb.crypto_secretstream_xchacha20poly1305_TAG_FINAL


class OpenError(Exception):
    pass


@dataclass
class Location:
    lat: float
    lon: float
    accuracy_m: float


def _policy_ad(policy: dict) -> bytes:
    return sha256(canon(policy))


def seal_file(src: str | Path, dst: str | Path, *, sender: Identity, recipient: PublicIdentity,
              policy: dict, lta: LTAClient) -> dict:
    """Encrypt `src` so that only `recipient`, inside `policy`'s zone and window, can open it."""
    if policy["recipient_sign_pk"] != recipient.sign_pk_b64:
        raise ValueError("policy recipient does not match the recipient identity")

    k_r, k_g = os.urandom(32), os.urandom(32)
    file_key = derive_file_key(k_r, k_g, policy)

    # K_G goes only to the LTA (sealed to its public key); K_R only to the recipient.
    ticket = lta.register(policy, SealedBox(lta.public_key()).encrypt(k_g), sender)
    wrapped_kr = SealedBox(recipient.enc_pk).encrypt(k_r)
    del k_r, k_g

    dst = Path(dst)
    ad = _policy_ad(policy)
    ct_hash = hashlib.sha256()
    state = nb.crypto_secretstream_xchacha20poly1305_state()
    ss_header = nb.crypto_secretstream_xchacha20poly1305_init_push(state, file_key)
    del file_key

    with tempfile.NamedTemporaryFile(dir=dst.parent or ".", delete=False) as tmp_ct, open(src, "rb") as fin:
        tmp_ct_path = Path(tmp_ct.name)
        chunk = fin.read(CHUNK)
        while True:
            nxt = fin.read(CHUNK)
            tag = TAG_FINAL if not nxt else TAG_MESSAGE
            c = nb.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, tag)
            ct_hash.update(c)
            tmp_ct.write(c)
            if tag == TAG_FINAL:
                break
            chunk = nxt

    try:
        header = {
            "v": 1,
            "lta_url": lta.base_url,
            "ticket": ticket,
            "policy": policy,
            "wrapped_kr": b64e(wrapped_kr),
            "stream_header": b64e(ss_header),
            "chunk_size": CHUNK,
            "ct_sha256": ct_hash.hexdigest(),
            "sender": {"name": sender.name, "sign_pk": b64e(bytes(sender.sign_sk.verify_key)),
                       "fingerprint": sender.public().fingerprint},
            "filename": Path(src).name,
        }
        sig = sender.sign_sk.sign(header_sig_message(header)).signature
        envelope = canon({"header": header, "sig": b64e(sig)})
        with open(dst, "wb") as out, open(tmp_ct_path, "rb") as ct_in:
            out.write(MAGIC + struct.pack(">I", len(envelope)) + envelope)
            while block := ct_in.read(1 << 20):
                out.write(block)
    finally:
        tmp_ct_path.unlink(missing_ok=True)
    return header


def read_envelope(path: str | Path) -> tuple[dict, bytes, int]:
    """Return (header, signature, offset of ciphertext). Does NOT verify the signature."""
    with open(path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise OpenError("not a HIG-TLC file")
        (n,) = struct.unpack(">I", f.read(4))
        if n > 16 * 1024 * 1024:
            raise OpenError("envelope too large")
        env = json.loads(f.read(n))
        return env["header"], b64d(env["sig"]), len(MAGIC) + 4 + n


def verify_header(header: dict, sig: bytes, expected_sender: PublicIdentity | None = None) -> None:
    sender_pk = header["sender"]["sign_pk"]
    if expected_sender is not None and sender_pk != expected_sender.sign_pk_b64:
        raise OpenError("file was not signed by the expected sender")
    try:
        VerifyKey(b64d(sender_pk)).verify(header_sig_message(header), sig)
    except BadSignatureError:
        raise OpenError("sender signature invalid: header has been tampered with") from None


def open_file(src: str | Path, dst: str | Path, *, recipient: Identity, location: Location,
              lta: LTAClient | None = None, expected_sender: PublicIdentity | None = None,
              beacon: Identity | None = None, dev_attestation: bool = False) -> dict:
    """Decrypt `src` to `dst`. Needs the recipient's private key AND the LTA's approval."""
    header, sig, offset = read_envelope(src)
    verify_header(header, sig, expected_sender)
    policy = header["policy"]
    me = recipient.public()
    if policy["recipient_sign_pk"] != me.sign_pk_b64:
        raise OpenError("this file is addressed to a different recipient")

    # Layer 1 - identity: only our X25519 key can unwrap K_R.
    try:
        k_r = SealedBox(recipient.enc_sk).decrypt(b64d(header["wrapped_kr"]))
    except CryptoError:
        raise OpenError("cannot unwrap K_R with this identity") from None

    # Layer 2 - place + time: ask the LTA for K_G with signed, nonce-bound evidence.
    lta = lta or LTAClient(header["lta_url"])
    ticket = header["ticket"]
    nonce = lta.nonce(ticket)
    reply_sk = PrivateKey.generate()  # one-time key so K_G is never sent in the clear
    body = {
        "ticket": ticket,
        "nonce": nonce,
        "lat": location.lat,
        "lon": location.lon,
        "accuracy_m": location.accuracy_m,
        "reply_pk": b64e(bytes(reply_sk.public_key)),
        "beacon_sig": None,
        "attestation": {"type": "dev", "nonce": nonce} if dev_attestation else None,
    }
    if beacon is not None:
        # Prototype stand-in: a real beacon signs only after UWB/RTT distance bounding.
        body["beacon_sig"] = b64e(beacon.sign_sk.sign(
            beacon_sig_message(nonce, ticket, me.sign_pk_b64)).signature)
    device_sig = recipient.sign_sk.sign(evidence_sig_message(body)).signature
    k_g = SealedBox(reply_sk).decrypt(lta.release(body, device_sig))
    del reply_sk

    file_key = derive_file_key(k_r, k_g, policy)
    del k_r, k_g
    _decrypt_stream(src, offset, dst, header, file_key)
    return header


def _decrypt_stream(src, offset: int, dst, header: dict, file_key: bytes) -> None:
    dst = Path(dst)
    ad = _policy_ad(header["policy"])
    state = nb.crypto_secretstream_xchacha20poly1305_state()
    nb.crypto_secretstream_xchacha20poly1305_init_pull(state, b64d(header["stream_header"]), file_key)
    ct_hash = hashlib.sha256()
    step = header["chunk_size"] + ABYTES
    tmp = tempfile.NamedTemporaryFile(dir=dst.parent or ".", delete=False)
    tmp_path = Path(tmp.name)
    ok = False
    try:
        with tmp, open(src, "rb") as fin:
            fin.seek(offset)
            final = False
            while c := fin.read(step):
                if final:
                    raise OpenError("data after final chunk")
                ct_hash.update(c)
                try:
                    m, tag = nb.crypto_secretstream_xchacha20poly1305_pull(state, c, ad)
                except CryptoError:
                    raise OpenError("ciphertext authentication failed (tampered or wrong key)") from None
                tmp.write(m)
                final = tag == TAG_FINAL
            if not final:
                raise OpenError("ciphertext truncated")
        if ct_hash.hexdigest() != header["ct_sha256"]:
            raise OpenError("ciphertext hash does not match signed header")
        os.replace(tmp_path, dst)
        ok = True
    finally:
        if not ok:
            tmp_path.unlink(missing_ok=True)
