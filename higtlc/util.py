"""Small shared helpers: canonical JSON, base64, HKDF, time parsing."""
import base64
import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timezone

PROTOCOL = "HIG-TLC v1"


def canon(obj) -> bytes:
    """Deterministic JSON encoding used for everything that gets hashed or signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """RFC 5869 HKDF with SHA-256."""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_file_key(k_r: bytes, k_g: bytes, policy: dict) -> bytes:
    """K_file = HKDF(K_R || K_G, info = protocol || SHA256(policy)).

    Binding the policy hash into the key means editing the policy in the
    header produces a different key, so decryption fails.
    """
    if len(k_r) != 32 or len(k_g) != 32:
        raise ValueError("key shares must be 32 bytes")
    info = f"{PROTOCOL} file-key|".encode() + sha256(canon(policy))
    return hkdf_sha256(k_r + k_g, info)


def header_sig_message(header: dict) -> bytes:
    return f"{PROTOCOL} header|".encode() + canon(header)


def register_sig_message(body: dict) -> bytes:
    return f"{PROTOCOL} register|".encode() + canon(body)


def evidence_sig_message(body: dict) -> bytes:
    return f"{PROTOCOL} evidence|".encode() + canon(body)


def beacon_sig_message(nonce: str, ticket: str, device_sign_pk: str) -> bytes:
    """What a site beacon signs after it has ranged the device (UWB / Wi-Fi RTT)."""
    return f"{PROTOCOL} beacon|".encode() + canon(
        {"nonce": nonce, "ticket": ticket, "device_sign_pk": device_sign_pk})


_DURATION = re.compile(r"^\+(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_time(text: str, now: float | None = None) -> int:
    """Accept 'now', '+30m' / '+2h' / '+1d', a unix timestamp, or ISO 8601."""
    now = time.time() if now is None else now
    text = text.strip()
    if text == "now":
        return int(now)
    m = _DURATION.match(text)
    if m:
        return int(now) + int(m.group(1)) * _UNITS[m.group(2)]
    if text.isdigit():
        return int(text)
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.astimezone()  # interpret naive times as local time
    return int(dt.timestamp())


def fmt_time(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
