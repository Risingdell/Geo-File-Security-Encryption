# Geo-Encryption — HIG-TLC prototype

**Hybrid Identity-Geographic Time-Locked Cryptosystem.** A file sealed with HIG-TLC opens only for
**one recipient**, **inside a geographic zone**, **during a time window**. After the window
closes, it can never be opened again.

## How it works

The file key is split into two random 256-bit shares. Neither share alone can decrypt the file:

```
K_file = HKDF-SHA256( K_R || K_G , info = "HIG-TLC v1" || SHA256(policy) )

K_R → sealed to the recipient's X25519 key          (proves IDENTITY)
K_G → held by the Location-Time Authority (LTA)     (proves PLACE + TIME)
```

| Step | Who | What |
|---|---|---|
| 1 | Sender | Generates `K_R`, `K_G`. Registers `K_G` + policy with the LTA (sealed to the LTA's key) and gets a ticket. |
| 2 | Sender | Encrypts the file with XChaCha20-Poly1305 (libsodium secretstream, 64 KiB chunks). Wraps `K_R` to the recipient. Signs the header with Ed25519. |
| 3 | Receiver | Verifies the sender's signature. Unwraps `K_R` with their private key. |
| 4 | Receiver | Gets a single-use nonce from the LTA. Sends signed evidence (location, accuracy, beacon proof, attestation) plus a one-time reply key. |
| 5 | LTA | Checks the recipient's signature, **its own clock**, GPS accuracy, the zone, the beacon and the attestation, and applies a rate limit. Returns `K_G` sealed to the reply key. Logs every attempt. |
| 6 | LTA | When `not_after` passes, **deletes `K_G`** (SQLite `secure_delete`). The file is then permanently unopenable. |

Why this beats a pure "Geo-KDF": location and time aren't secrets. If the receiver's own device
derived the key from GPS input, the receiver could just type in the target coordinates. Here, the
place and time check happens on a server that holds half of the key.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[test]"      # Linux/macOS: .venv/bin/pip

# 1. Start the Location-Time Authority
higtlc lta serve --state lta_state --port 8765

# 2. Create identities (prompts for a passphrase; or set HIGTLC_PASSPHRASE)
higtlc keygen --name alice --out alice.id    # writes alice.id (secret) + alice.pub
higtlc keygen --name bob   --out bob.id
higtlc keygen --name site  --out site.id     # optional: a site beacon

# 3. Alice seals a file for Bob: 50 m around a point, next 2 hours, beacon required
higtlc seal report.pdf --from alice.id --to bob.pub --lta http://127.0.0.1:8765 \
    --circle 28.6129,77.2295,50 --not-after +2h --beacon site.pub

higtlc inspect report.pdf.hig

# 4. Bob opens it on site (location is passed in by hand in this prototype)
higtlc open report.pdf.hig --id bob.id --sender alice.pub \
    --lat 28.61295 --lon 77.22955 --accuracy 8 --beacon-key site.id
```

Zones: `--circle LAT,LON,RADIUS_M` or `--polygon "LAT,LON;LAT,LON;LAT,LON"`.

## Transferring a file between two people (HTTP or HTTPS)

To see the whole flow on one machine (Alice, Bob and the server in separate folders), run:
`powershell -ExecutionPolicy Bypass -File demo\two_person_demo.ps1` (add `-Scheme http` for plain HTTP).

The server runs the **LTA** (holds `K_G`) and a **relay** (an untrusted mailbox that carries sealed
files). The relay and the network only ever see ciphertext.

```
 Alice (sender)                    Server (LTA + relay)                 Bob (receiver)
 seal: K_R → Bob's public key ──►  /v1/register  (K_G + policy)
       file → XChaCha20        ──►  /v1/relay/files  (.hig upload)
                                    /v1/relay/inbox  ◄── signed by Bob ── inbox / receive
                                    /v1/relay/files/ID ──────────────────► download .hig
                                                                          private key → K_R
                                    /v1/release ◄── device location + ── evidence signed by Bob
                                    checks zone + server clock ─── K_G ─► K_file = HKDF(K_R‖K_G)
                                                                          file opens
```

**0. Server operator** (any machine both people can reach; use its LAN or public IP):
```powershell
higtlc tls-cert --host 192.168.1.5 --out certs            # HTTPS; skip for plain HTTP
higtlc serve --host 0.0.0.0 --port 8765 --tls-cert certs/server.crt --tls-key certs/server.key
```
Give `certs/ca.crt` to both people. With plain HTTP, drop the `--tls-*` and `--ca` options and use `http://`.

**1. Each person creates an identity once and swaps `.pub` files** (compare fingerprints by phone or in person):
```powershell
higtlc keygen --name bob --out bob.id        # Bob sends bob.pub to Alice
higtlc keygen --name alice --out alice.id    # Alice sends alice.pub to Bob
```

**2. Bob finds the coordinates of the place where he'll open the file** (or Alice picks them from a map):
```powershell
higtlc locate
```

**3. Alice seals and sends:**
```powershell
higtlc seal plan.pdf --from alice.id --to bob.pub --ca ca.crt `
    --lta https://192.168.1.5:8765 --circle 12.872323,74.940850,200 --max-accuracy 100 `
    --not-after +2h --send
```

**4. Bob receives and opens.** His location is captured from the device automatically:
```powershell
higtlc inbox   --id bob.id --server https://192.168.1.5:8765 --ca ca.crt
higtlc receive --id bob.id --server https://192.168.1.5:8765 --ca ca.crt `
    --sender alice.pub --open --launch
```

Laptops without GPS get their position from Wi-Fi, usually with 50–150 m error. Choose `--circle`
radius and `--max-accuracy` to suit (for example, 200 m / 100 m). Phones with GPS can use tighter
values. Location services must be on (Windows: Settings → Privacy & security → Location).
Times: `now`, `+30m`, `+2h`, `+1d`, a unix timestamp, or ISO 8601.

Run the tests with `pytest`. They cover the happy path, wrong place, wrong time, expiry, wrong
recipient, forged sender, tampered header/ciphertext, nonce replay, beacon, attestation, rate limit
and audit log, and show that a compromised LTA can't decrypt.

## Layout

| File | Purpose |
|---|---|
| [higtlc/container.py](higtlc/container.py) | `.hig` format, `seal_file` / `open_file` |
| [higtlc/lta_server.py](higtlc/lta_server.py) | FastAPI LTA: `/v1/info`, `/v1/register`, `/v1/nonce`, `/v1/release` |
| [higtlc/lta_client.py](higtlc/lta_client.py) | HTTP(S) clients for the LTA and the relay |
| [higtlc/relay.py](higtlc/relay.py) | Relay: upload, signed inbox listing, download, delete |
| [higtlc/location.py](higtlc/location.py) | Device location via the Windows location service |
| [higtlc/tls.py](higtlc/tls.py) | Private CA + server certificate for HTTPS |
| [higtlc/policy.py](higtlc/policy.py) | Policy schema, circle/polygon zone checks |
| [higtlc/keys.py](higtlc/keys.py) | X25519 + Ed25519 identities, Argon2id-encrypted at rest |
| [higtlc/util.py](higtlc/util.py) | Canonical JSON, HKDF, signed-message domains, time parsing |
| [higtlc/cli.py](higtlc/cli.py) | `higtlc` command |

## Security status — read before trusting it

This is a **prototype**. It hasn't been audited.

- **Location is self-reported.** It's read from the OS location service (or typed in with
  `--lat/--lon`), and a modified client could report any position. Real protection needs device attestation
  (Play Integrity / App Attest) and ideally a **site beacon** that signs only after UWB
  distance bounding. The protocol checks both already. `--beacon-key` and `--dev-attestation` are
  **simulations**, and the LTA accepts stub attestations only when started with `--dev-attestation`.
- **The LTA is trusted** for place and time, but it can't read files (it never sees `K_R`). A
  malicious LTA *could* release `K_G` to the recipient early. Splitting `K_G` across several LTAs
  (for example, 2-of-3 Shamir) removes that single point of trust.
- **Run the LTA behind TLS.** `K_G` is sealed end-to-end anyway, but TLS protects metadata.
- **`lta_state/lta_key.json` is the LTA master key.** In production, keep it in an HSM/KMS.
- Plaintext written to disk can be copied. Cryptography can't stop that once a file is opened.
- Python can't reliably wipe secrets from memory. A production client belongs in Kotlin/Swift/Rust
  with keys in StrongBox / Secure Enclave behind biometrics.

## Roadmap

1. Android receiver: Keystore/StrongBox + BiometricPrompt, FusedLocation, Wi-Fi RTT, Play Integrity.
2. Real attestation verifier in `lta_server.verify_attestation`.
3. UWB site beacon (Raspberry Pi + TPM + UWB module) that does distance bounding.
4. Threshold LTAs (Shamir 2-of-3 for `K_G`).
5. Append-only transparency log for LTA decisions.
6. Optional drand `tlock` wrapping for a "not before" lock that doesn't depend on the LTA.
