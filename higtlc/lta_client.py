"""HTTP(S) clients for the Location-Time Authority and the file relay."""
import os
import ssl
import time
from pathlib import Path

import httpx
from nacl.public import PublicKey

from .keys import Identity
from .util import b64d, b64e, register_sig_message


class LTAError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(f"server refused ({status}): {reason}")
        self.status, self.reason = status, reason


def tls_verify(ca_file: str | None = None) -> ssl.SSLContext | bool:
    """TLS trust for https:// URLs. `ca_file` (or $HIGTLC_CA) trusts a self-signed server cert."""
    ca_file = ca_file or os.environ.get("HIGTLC_CA")
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return True


class _Client:
    def __init__(self, base_url: str, http: httpx.Client | None = None, ca_file: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.http = http or httpx.Client(base_url=self.base_url, timeout=60, verify=tls_verify(ca_file))

    def _call(self, method: str, path: str, **kw) -> httpx.Response:
        try:
            r = self.http.request(method, path, **kw)
        except httpx.HTTPError as e:
            raise LTAError(0, f"cannot reach {self.base_url}: {e}") from None
        if r.status_code != 200:
            try:
                reason = r.json().get("detail", r.text)
            except ValueError:
                reason = r.text
            raise LTAError(r.status_code, str(reason))
        return r


class LTAClient(_Client):
    def public_key(self) -> PublicKey:
        return PublicKey(b64d(self._call("GET", "/v1/info").json()["lta_enc_pk"]))

    def register(self, policy: dict, sealed_kg: bytes, sender: Identity) -> str:
        body = {"policy": policy, "sealed_kg": b64e(sealed_kg),
                "sender_sign_pk": b64e(bytes(sender.sign_sk.verify_key))}
        sig = sender.sign_sk.sign(register_sig_message(body)).signature
        return self._call("POST", "/v1/register", json={"body": body, "sig": b64e(sig)}).json()["ticket"]

    def nonce(self, ticket: str) -> str:
        return self._call("POST", "/v1/nonce", json={"ticket": ticket}).json()["nonce"]

    def release(self, body: dict, device_sig: bytes) -> bytes:
        r = self._call("POST", "/v1/release", json={"body": body, "device_sig": b64e(device_sig)})
        return b64d(r.json()["sealed_kg"])


class RelayClient(_Client):
    """Moves sealed .hig files between people over plain HTTP or HTTPS."""

    def _auth(self, me: Identity) -> dict:
        from .relay import inbox_sig_message
        pk, ts = b64e(bytes(me.sign_sk.verify_key)), int(time.time())
        return {"recipient": pk, "ts": ts, "sig": b64e(me.sign_sk.sign(inbox_sig_message(pk, ts)).signature)}

    def upload(self, path: str | Path) -> str:
        with open(path, "rb") as f:
            return self._call("POST", "/v1/relay/files", content=f,
                              headers={"content-type": "application/octet-stream"}).json()["id"]

    def inbox(self, me: Identity) -> list[dict]:
        return self._call("GET", "/v1/relay/inbox", params=self._auth(me)).json()["files"]

    def download(self, file_id: str, dst: str | Path) -> None:
        try:
            with self.http.stream("GET", f"/v1/relay/files/{file_id}") as r:
                if r.status_code != 200:
                    r.read()
                    raise LTAError(r.status_code, r.text)
                with open(dst, "wb") as f:
                    for block in r.iter_bytes():
                        f.write(block)
        except httpx.HTTPError as e:
            raise LTAError(0, f"cannot reach {self.base_url}: {e}") from None

    def delete(self, me: Identity, file_id: str) -> None:
        self._call("DELETE", f"/v1/relay/files/{file_id}", params=self._auth(me))
