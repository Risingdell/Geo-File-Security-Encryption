"""HTTP client for the Location-Time Authority."""
import httpx
from nacl.public import PublicKey

from .keys import Identity
from .util import b64d, b64e, register_sig_message


class LTAError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(f"LTA refused ({status}): {reason}")
        self.status, self.reason = status, reason


class LTAClient:
    def __init__(self, base_url: str, http: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.http = http or httpx.Client(base_url=self.base_url, timeout=15)

    def _call(self, method: str, path: str, json: dict | None = None) -> dict:
        try:
            r = self.http.request(method, path, json=json)
        except httpx.HTTPError as e:
            raise LTAError(0, f"cannot reach LTA at {self.base_url}: {e}") from None
        if r.status_code != 200:
            try:
                reason = r.json().get("detail", r.text)
            except ValueError:
                reason = r.text
            raise LTAError(r.status_code, str(reason))
        return r.json()

    def public_key(self) -> PublicKey:
        return PublicKey(b64d(self._call("GET", "/v1/info")["lta_enc_pk"]))

    def register(self, policy: dict, sealed_kg: bytes, sender: Identity) -> str:
        body = {"policy": policy, "sealed_kg": b64e(sealed_kg),
                "sender_sign_pk": b64e(bytes(sender.sign_sk.verify_key))}
        sig = sender.sign_sk.sign(register_sig_message(body)).signature
        return self._call("POST", "/v1/register", {"body": body, "sig": b64e(sig)})["ticket"]

    def nonce(self, ticket: str) -> str:
        return self._call("POST", "/v1/nonce", {"ticket": ticket})["nonce"]

    def release(self, body: dict, device_sig: bytes) -> bytes:
        return b64d(self._call("POST", "/v1/release", {"body": body, "device_sig": b64e(device_sig)})["sealed_kg"])
