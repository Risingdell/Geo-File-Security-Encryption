"""File relay: an untrusted mailbox that carries sealed .hig files between people.

It stores only ciphertext. Opening a file still needs the recipient's private key
AND the LTA's place/time approval, so the relay (or anyone snooping on HTTP)
learns nothing but metadata.
"""
import json
import os
import time
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .container import OpenError, read_envelope, verify_header
from .util import PROTOCOL, b64d, canon

MAX_UPLOAD = 512 * 1024 * 1024
INBOX_AUTH_SKEW_S = 300


def inbox_sig_message(recipient_sign_pk: str, ts: int) -> bytes:
    return f"{PROTOCOL} inbox|".encode() + canon({"recipient": recipient_sign_pk, "ts": ts})


def create_relay_router(relay_dir: Path, clock: Callable[[], float] = time.time) -> APIRouter:
    relay_dir.mkdir(parents=True, exist_ok=True)
    router = APIRouter(prefix="/v1/relay")

    def _meta_path(file_id: str) -> Path:
        if not file_id.isalnum():
            raise HTTPException(400, "bad file id")
        return relay_dir / f"{file_id}.json"

    @router.post("/files")
    async def upload(request: Request):
        file_id = os.urandom(12).hex()
        blob = relay_dir / f"{file_id}.hig"
        size = 0
        try:
            with open(blob, "wb") as f:
                async for part in request.stream():
                    size += len(part)
                    if size > MAX_UPLOAD:
                        raise HTTPException(413, "file too large")
                    f.write(part)
            # Reject anything that isn't a correctly signed HIG-TLC file.
            header, sig, _ = read_envelope(blob)
            verify_header(header, sig)
        except (OpenError, ValueError, KeyError) as e:
            blob.unlink(missing_ok=True)
            raise HTTPException(400, f"not a valid sealed file: {e}") from None
        except HTTPException:
            blob.unlink(missing_ok=True)
            raise
        meta = {
            "id": file_id,
            "recipient": header["policy"]["recipient_sign_pk"],
            "filename": header["filename"],
            "sender": header["sender"],
            "size": size,
            "uploaded": int(clock()),
            "not_after": header["policy"]["not_after"],
        }
        _meta_path(file_id).write_text(json.dumps(meta))
        return {"id": file_id, "size": size}

    def _authenticate(recipient: str, ts: int, sig: str) -> None:
        if abs(clock() - ts) > INBOX_AUTH_SKEW_S:
            raise HTTPException(401, "stale inbox request; check your clock")
        try:
            VerifyKey(b64d(recipient)).verify(inbox_sig_message(recipient, ts), b64d(sig))
        except (BadSignatureError, ValueError):
            raise HTTPException(401, "inbox signature invalid") from None

    @router.get("/inbox")
    def inbox(recipient: str, ts: int, sig: str):
        # Only the recipient may list their inbox (prevents metadata harvesting).
        _authenticate(recipient, ts, sig)
        items = []
        for p in sorted(relay_dir.glob("*.json")):
            meta = json.loads(p.read_text())
            if meta["recipient"] == recipient:
                items.append({k: v for k, v in meta.items() if k != "recipient"})
        return {"files": sorted(items, key=lambda m: m["uploaded"])}

    @router.get("/files/{file_id}")
    def download(file_id: str):
        meta_path = _meta_path(file_id)
        if not meta_path.exists():
            raise HTTPException(404, "no such file")
        meta = json.loads(meta_path.read_text())
        return FileResponse(relay_dir / f"{file_id}.hig", media_type="application/octet-stream",
                            filename=meta["filename"] + ".hig")

    @router.delete("/files/{file_id}")
    def delete(file_id: str, recipient: str, ts: int, sig: str):
        _authenticate(recipient, ts, sig)
        meta_path = _meta_path(file_id)
        if not meta_path.exists():
            raise HTTPException(404, "no such file")
        if json.loads(meta_path.read_text())["recipient"] != recipient:
            raise HTTPException(403, "only the recipient can delete this file")
        meta_path.unlink()
        (relay_dir / f"{file_id}.hig").unlink(missing_ok=True)
        return {"deleted": file_id}

    return router
