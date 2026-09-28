"""Location-Time Authority (LTA).

Holds share K_G for each sealed file and releases it only when the recipient
proves identity + place + time. It never sees K_R, so it cannot decrypt files.
When a policy's window closes, K_G is deleted, so the file can never be opened again.
"""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, HTTPException
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import VerifyKey
from pydantic import BaseModel

from .policy import PolicyError, in_zone, validate_policy
from .util import (b64d, b64e, beacon_sig_message, evidence_sig_message,
                   register_sig_message)

NONCE_TTL_S = 60
MAX_FAILURES_PER_HOUR = 5


class RegisterReq(BaseModel):
    body: dict  # {"policy": {...}, "sealed_kg": b64, "sender_sign_pk": b64}
    sig: str


class NonceReq(BaseModel):
    ticket: str


class ReleaseReq(BaseModel):
    body: dict  # {"ticket","nonce","lat","lon","accuracy_m","reply_pk","beacon_sig","attestation"}
    device_sig: str


class Denied(Exception):
    def __init__(self, reason: str, status: int = 403):
        super().__init__(reason)
        self.reason, self.status = reason, status


def _load_or_create_key(state_dir: Path) -> PrivateKey:
    path = state_dir / "lta_key.json"
    if path.exists():
        return PrivateKey(b64d(json.loads(path.read_text())["enc_sk"]))
    sk = PrivateKey.generate()
    path.write_text(json.dumps({"enc_sk": b64e(bytes(sk))}))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return sk


class Store:
    def __init__(self, db_path: Path):
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.lock = threading.Lock()
        with self.lock:
            # Overwrite deleted content on disk so expired K_G shares don't linger.
            self.db.execute("PRAGMA secure_delete = ON")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS tickets (
                    ticket TEXT PRIMARY KEY, policy TEXT NOT NULL, sealed_kg BLOB NOT NULL,
                    sender_sign_pk TEXT NOT NULL, created INTEGER NOT NULL, not_after INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY, ticket TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ticket TEXT,
                    action TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT, detail TEXT);
            """)

    def q(self, sql: str, args=()) -> list:
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def audit(self, now: float, ticket, action, outcome, reason=None, detail=None):
        self.q("INSERT INTO audit (ts, ticket, action, outcome, reason, detail) VALUES (?,?,?,?,?,?)",
               (int(now), ticket, action, outcome, reason, json.dumps(detail) if detail else None))


def create_app(state_dir: str | Path, *, clock: Callable[[], float] = time.time,
               dev_attestation: bool = False, relay: bool = True) -> FastAPI:
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    lta_sk = _load_or_create_key(state_dir)
    store = Store(state_dir / "lta.sqlite3")
    app = FastAPI(title="HIG-TLC Location-Time Authority")
    app.state.store = store
    if relay:
        from .relay import create_relay_router
        app.include_router(create_relay_router(state_dir / "relay", clock))

    def purge_expired(now: float) -> None:
        expired = store.q("SELECT ticket FROM tickets WHERE not_after < ?", (int(now),))
        for (ticket,) in expired:
            store.q("DELETE FROM tickets WHERE ticket = ?", (ticket,))
            store.audit(now, ticket, "purge", "deleted", "window closed; K_G destroyed")
        store.q("DELETE FROM nonces WHERE expires < ?", (int(now),))

    app.state.purge_expired = lambda: purge_expired(clock())
    purge_expired(clock())

    def verify_attestation(att: dict | None, nonce: str) -> bool:
        # Plug a real verifier in here (Play Integrity / App Attest token check,
        # confirming the token's nonce equals `nonce`). Dev mode accepts a stub.
        return dev_attestation and bool(att) and att.get("type") == "dev" and att.get("nonce") == nonce

    @app.get("/v1/info")
    def info():
        return {"protocol": "HIG-TLC v1", "lta_enc_pk": b64e(bytes(lta_sk.public_key)), "time": int(clock())}

    @app.post("/v1/register")
    def register(req: RegisterReq):
        now = clock()
        purge_expired(now)
        try:
            body = req.body
            policy, sender_pk = body["policy"], body["sender_sign_pk"]
            VerifyKey(b64d(sender_pk)).verify(register_sig_message(body), b64d(req.sig))
            validate_policy(policy)
            if policy["not_after"] <= now:
                raise PolicyError("policy window has already closed")
            sealed_kg = b64d(body["sealed_kg"])
            if len(SealedBox(lta_sk).decrypt(sealed_kg)) != 32:
                raise PolicyError("K_G must be 32 bytes")
        except (KeyError, TypeError, ValueError, BadSignatureError, CryptoError) as e:
            raise HTTPException(400, f"invalid registration: {e}") from None
        ticket = b64e(os.urandom(18)).replace("+", "-").replace("/", "_")
        # K_G stays sealed to the LTA key at rest; lta_key.json is the master key.
        store.q("INSERT INTO tickets VALUES (?,?,?,?,?,?)",
                (ticket, json.dumps(policy), sealed_kg, sender_pk, int(now), policy["not_after"]))
        store.audit(now, ticket, "register", "ok", detail={"sender_sign_pk": sender_pk})
        return {"ticket": ticket}

    @app.post("/v1/nonce")
    def nonce(req: NonceReq):
        now = clock()
        purge_expired(now)
        if not store.q("SELECT 1 FROM tickets WHERE ticket = ?", (req.ticket,)):
            raise HTTPException(404, "unknown or expired ticket")
        n = b64e(os.urandom(24))
        store.q("INSERT INTO nonces VALUES (?,?,?)", (n, req.ticket, int(now) + NONCE_TTL_S))
        return {"nonce": n, "expires": int(now) + NONCE_TTL_S}

    @app.post("/v1/release")
    def release(req: ReleaseReq):
        now = clock()
        purge_expired(now)
        body = req.body
        ticket = body.get("ticket")
        try:
            sealed_for_receiver = _check_and_release(body, req.device_sig, ticket, now)
        except Denied as d:
            store.audit(now, ticket, "release", "denied", d.reason,
                        {"lat": body.get("lat"), "lon": body.get("lon"), "accuracy_m": body.get("accuracy_m")})
            raise HTTPException(d.status, d.reason) from None
        store.audit(now, ticket, "release", "granted",
                    detail={"lat": body["lat"], "lon": body["lon"], "accuracy_m": body["accuracy_m"]})
        return {"sealed_kg": b64e(sealed_for_receiver)}

    def _check_and_release(body: dict, device_sig: str, ticket, now: float) -> bytes:
        rows = store.q("SELECT policy, sealed_kg FROM tickets WHERE ticket = ?", (ticket,))
        if not rows:
            raise Denied("unknown or expired ticket", 404)
        policy, sealed_kg = json.loads(rows[0][0]), rows[0][1]

        failures = store.q("SELECT COUNT(*) FROM audit WHERE ticket = ? AND action = 'release' "
                           "AND outcome = 'denied' AND ts > ?", (ticket, int(now) - 3600))[0][0]
        if failures >= MAX_FAILURES_PER_HOUR:
            raise Denied("too many failed attempts; try again later", 429)

        # Nonce: must exist, belong to this ticket, be fresh. Consumed on first use either way.
        nonce = body.get("nonce")
        row = store.q("DELETE FROM nonces WHERE nonce = ? RETURNING ticket, expires", (nonce,))
        if not row or row[0][0] != ticket or row[0][1] < now:
            raise Denied("invalid, reused or expired nonce")

        # Identity: evidence must be signed by the recipient named in the policy.
        try:
            VerifyKey(b64d(policy["recipient_sign_pk"])).verify(evidence_sig_message(body), b64d(device_sig))
        except (BadSignatureError, ValueError):
            raise Denied("evidence not signed by the policy's recipient") from None

        # Time: the LTA's own clock, never the device's.
        if now < policy["not_before"]:
            raise Denied("time window not open yet")
        if now > policy["not_after"]:
            raise Denied("time window closed")

        # Place.
        try:
            lat, lon, acc = float(body["lat"]), float(body["lon"]), float(body["accuracy_m"])
        except (KeyError, TypeError, ValueError):
            raise Denied("malformed location evidence", 400) from None
        if not 0 < acc <= policy["max_accuracy_m"]:
            raise Denied(f"location accuracy {acc:g} m exceeds limit {policy['max_accuracy_m']:g} m")
        if not in_zone(policy["zone"], lat, lon):
            raise Denied("location outside the permitted zone")

        # Physical presence: site beacon countersignature (after UWB / RTT ranging).
        if policy.get("beacon_pk"):
            try:
                VerifyKey(b64d(policy["beacon_pk"])).verify(
                    beacon_sig_message(nonce, ticket, policy["recipient_sign_pk"]),
                    b64d(body.get("beacon_sig") or ""))
            except (BadSignatureError, ValueError):
                raise Denied("missing or invalid site-beacon proof") from None

        # Device integrity.
        if policy.get("require_attestation") and not verify_attestation(body.get("attestation"), nonce):
            raise Denied("device attestation missing or invalid")

        # All checks passed: re-seal K_G to the receiver's one-time reply key.
        try:
            reply_pk = PublicKey(b64d(body["reply_pk"]))
        except (KeyError, TypeError, ValueError):
            raise Denied("malformed reply key", 400) from None
        k_g = SealedBox(lta_sk).decrypt(sealed_kg)
        return SealedBox(reply_pk).encrypt(k_g)

    return app
