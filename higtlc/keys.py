"""Identities: an X25519 key (receives wrapped K_R) plus an Ed25519 key (signs).

Private identity files are encrypted with a passphrase via Argon2id + XSalsa20-Poly1305.
Argon2id is the right tool here because a passphrase is low-entropy.
"""
import json
import os
from dataclasses import dataclass
from pathlib import Path

from nacl import pwhash, secret
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from .util import b64d, b64e, sha256


def fingerprint(enc_pk: bytes, sign_pk: bytes) -> str:
    h = sha256(b"HIG-TLC fp|" + enc_pk + sign_pk).hex()[:32]
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


@dataclass
class PublicIdentity:
    name: str
    enc_pk: PublicKey
    sign_pk: VerifyKey

    @property
    def sign_pk_b64(self) -> str:
        return b64e(bytes(self.sign_pk))

    @property
    def fingerprint(self) -> str:
        return fingerprint(bytes(self.enc_pk), bytes(self.sign_pk))

    def to_dict(self) -> dict:
        return {
            "type": "higtlc-public-identity",
            "name": self.name,
            "enc_pk": b64e(bytes(self.enc_pk)),
            "sign_pk": self.sign_pk_b64,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PublicIdentity":
        pub = cls(d["name"], PublicKey(b64d(d["enc_pk"])), VerifyKey(b64d(d["sign_pk"])))
        if d.get("fingerprint") and d["fingerprint"] != pub.fingerprint:
            raise ValueError("public identity fingerprint mismatch")
        return pub


@dataclass
class Identity:
    name: str
    enc_sk: PrivateKey
    sign_sk: SigningKey

    @classmethod
    def generate(cls, name: str) -> "Identity":
        return cls(name, PrivateKey.generate(), SigningKey.generate())

    def public(self) -> PublicIdentity:
        return PublicIdentity(self.name, self.enc_sk.public_key, self.sign_sk.verify_key)


# Moderate cost: ~0.5 s and 256 MiB on a laptop.
_OPS = pwhash.argon2id.OPSLIMIT_MODERATE
_MEM = pwhash.argon2id.MEMLIMIT_MODERATE


def save_identity(ident: Identity, path: str | Path, passphrase: str) -> None:
    salt = os.urandom(pwhash.argon2id.SALTBYTES)
    kek = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, passphrase.encode(), salt,
                              opslimit=_OPS, memlimit=_MEM)
    plaintext = json.dumps({
        "name": ident.name,
        "enc_sk": b64e(bytes(ident.enc_sk)),
        "sign_sk": b64e(bytes(ident.sign_sk)),
    }).encode()
    doc = {
        "type": "higtlc-private-identity",
        "name": ident.name,
        "kdf": {"alg": "argon2id", "salt": b64e(salt), "ops": _OPS, "mem": _MEM},
        "box": b64e(secret.SecretBox(kek).encrypt(plaintext)),
    }
    Path(path).write_text(json.dumps(doc, indent=2))


def load_identity(path: str | Path, passphrase: str) -> Identity:
    doc = json.loads(Path(path).read_text())
    if doc.get("type") != "higtlc-private-identity":
        raise ValueError(f"{path} is not a private identity file")
    kdf = doc["kdf"]
    kek = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, passphrase.encode(), b64d(kdf["salt"]),
                              opslimit=kdf["ops"], memlimit=kdf["mem"])
    try:
        inner = json.loads(secret.SecretBox(kek).decrypt(b64d(doc["box"])))
    except Exception:
        raise ValueError("wrong passphrase or corrupted identity file") from None
    return Identity(inner["name"], PrivateKey(b64d(inner["enc_sk"])), SigningKey(b64d(inner["sign_sk"])))


def save_public(pub: PublicIdentity, path: str | Path) -> None:
    Path(path).write_text(json.dumps(pub.to_dict(), indent=2))


def load_public(path: str | Path) -> PublicIdentity:
    return PublicIdentity.from_dict(json.loads(Path(path).read_text()))
