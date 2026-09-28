"""Command-line interface.

    higtlc keygen | fingerprint | locate
    higtlc serve  | tls-cert                       (server operator)
    higtlc seal [--send] | send                    (sender)
    higtlc inbox | receive [--open] | open         (receiver)
"""
import argparse
import getpass
import os
import sys
from pathlib import Path

from .container import Location, OpenError, open_file, read_envelope, seal_file, verify_header
from .keys import Identity, load_identity, load_public, save_identity, save_public
from .lta_client import LTAClient, LTAError, RelayClient
from .policy import PolicyError, circle_zone, describe_zone, make_policy, polygon_zone
from .util import fmt_time, parse_time


def _passphrase(label: str, confirm: bool = False) -> str:
    env = os.environ.get("HIGTLC_PASSPHRASE")
    if env is not None:
        return env
    p = getpass.getpass(f"Passphrase for {label}: ")
    if confirm and p != getpass.getpass("Repeat passphrase: "):
        sys.exit("passphrases do not match")
    return p


def _apply_ca(a) -> None:
    # Clients built anywhere (including from a file header's LTA URL) pick this up.
    if getattr(a, "ca", None):
        os.environ["HIGTLC_CA"] = a.ca


# ---------------------------------------------------------------- identities

def cmd_keygen(a):
    out = Path(a.out)
    pub_path = out.with_suffix(".pub")
    if out.exists() and not a.force:
        sys.exit(f"{out} exists (use --force to overwrite)")
    ident = Identity.generate(a.name)
    save_identity(ident, out, _passphrase(str(out), confirm=True))
    save_public(ident.public(), pub_path)
    print(f"private identity: {out}   (keep secret)")
    print(f"public identity:  {pub_path}   (share this)")
    print(f"fingerprint:      {ident.public().fingerprint}")


def cmd_fingerprint(a):
    pub = load_public(a.pub)
    print(f"{pub.name}: {pub.fingerprint}")


def cmd_locate(a):
    from .location import current_location
    loc = current_location()
    print(f"lat={loc.lat:.6f} lon={loc.lon:.6f} accuracy={loc.accuracy_m:g} m")
    print(f"use as zone:  --circle {loc.lat:.6f},{loc.lon:.6f},<RADIUS_M>")


# ---------------------------------------------------------------- server

def cmd_serve(a):
    import uvicorn
    from .lta_server import create_app
    if a.dev_attestation:
        print("WARNING: --dev-attestation accepts stub attestations. Never use in production.")
    if bool(a.tls_cert) != bool(a.tls_key):
        sys.exit("--tls-cert and --tls-key must be given together")
    scheme = "https" if a.tls_cert else "http"
    print(f"HIG-TLC server (LTA + relay) on {scheme}://{a.host}:{a.port}")
    uvicorn.run(create_app(a.state, dev_attestation=a.dev_attestation, relay=not a.no_relay),
                host=a.host, port=a.port, ssl_certfile=a.tls_cert, ssl_keyfile=a.tls_key)


def cmd_tls_cert(a):
    from .tls import generate
    paths = generate(a.host, a.out)
    print(f"CA certificate:     {paths['ca']}   (give to every client: --ca {paths['ca']})")
    print(f"server certificate: {paths['cert']}")
    print(f"server key:         {paths['key']}   (keep on the server)")
    print(f"start:  higtlc serve --host 0.0.0.0 --tls-cert {paths['cert']} --tls-key {paths['key']}")


# ---------------------------------------------------------------- sender

def _zone(a) -> dict:
    if a.circle:
        lat, lon, r = (float(x) for x in a.circle.split(","))
        return circle_zone(lat, lon, r)
    pts = [tuple(float(x) for x in p.split(",")) for p in a.polygon.split(";") if p.strip()]
    return polygon_zone(pts)


def cmd_seal(a):
    _apply_ca(a)
    sender = load_identity(a.sender, _passphrase(a.sender))
    recipient = load_public(a.to)
    beacon_pk = load_public(a.beacon).sign_pk_b64 if a.beacon else None
    policy = make_policy(
        recipient_sign_pk=recipient.sign_pk_b64,
        zone=_zone(a),
        not_before=parse_time(a.not_before),
        not_after=parse_time(a.not_after),
        max_accuracy_m=a.max_accuracy,
        beacon_pk=beacon_pk,
        require_attestation=a.require_attestation,
    )
    out = a.output or f"{a.file}.hig"
    seal_file(a.file, out, sender=sender, recipient=recipient, policy=policy, lta=LTAClient(a.lta))
    print(f"[1] asymmetric layer: K_R sealed to {recipient.name}'s public key [{recipient.fingerprint}]")
    print(f"[2] place layer:      {describe_zone(policy['zone'])}, GPS error <= {policy['max_accuracy_m']:g} m")
    print(f"[3] time layer:       {fmt_time(policy['not_before'])}  ->  {fmt_time(policy['not_after'])}")
    print(f"sealed -> {out}")
    if a.send:
        file_id = RelayClient(a.relay or a.lta).upload(out)
        print(f"sent over {(a.relay or a.lta).split(':')[0].upper()} -> relay file id {file_id}")


def cmd_send(a):
    _apply_ca(a)
    header, sig, _ = read_envelope(a.file)
    verify_header(header, sig)
    file_id = RelayClient(a.server).upload(a.file)
    print(f"sent {a.file} -> {a.server}  (file id {file_id})")


def cmd_inspect(a):
    header, sig, _ = read_envelope(a.file)
    verify_header(header, sig)
    p = header["policy"]
    print(f"file:        {header['filename']}")
    print(f"sender:      {header['sender']['name']} [{header['sender']['fingerprint']}]  (signature OK)")
    print(f"LTA:         {header['lta_url']}")
    print(f"zone:        {describe_zone(p['zone'])}")
    print(f"window:      {fmt_time(p['not_before'])}  ->  {fmt_time(p['not_after'])}")
    print(f"max GPS err: {p['max_accuracy_m']:g} m")
    print(f"beacon:      {'required' if p['beacon_pk'] else 'not required'}")
    print(f"attestation: {'required' if p['require_attestation'] else 'not required'}")


# ---------------------------------------------------------------- receiver

def cmd_inbox(a):
    _apply_ca(a)
    me = load_identity(a.id, _passphrase(a.id))
    files = RelayClient(a.server).inbox(me)
    if not files:
        print("inbox empty")
    for f in files:
        print(f"{f['id']}  {f['filename']:<30} {f['size']:>10} B  from {f['sender']['name']} "
              f"[{f['sender']['fingerprint']}]  open until {fmt_time(f['not_after'])}")


def _location(a) -> Location:
    if a.lat is not None and a.lon is not None:
        return Location(a.lat, a.lon, a.accuracy)
    if (a.lat is None) != (a.lon is None):
        sys.exit("give both --lat and --lon, or neither to use the device location")
    from .location import current_location
    print("capturing device location ...")
    loc = current_location()
    print(f"    lat={loc.lat:.6f} lon={loc.lon:.6f} accuracy={loc.accuracy_m:g} m")
    return loc


def _open_one(a, recipient: Identity, path: Path, out: Path, beacon, expected, loc: Location) -> None:
    header, _, _ = read_envelope(path)
    lta = LTAClient(a.lta) if a.lta else None
    print(f"opening {path.name}")
    print(f"[1] private key unwraps K_R ... [2]+[3] LTA {a.lta or header['lta_url']} checks place + time ...")
    open_file(path, out, recipient=recipient, location=loc, lta=lta, expected_sender=expected,
              beacon=beacon, dev_attestation=a.dev_attestation)
    if expected is None:
        print(f"WARNING: sender not pinned. Signed by {header['sender']['name']} "
              f"[{header['sender']['fingerprint']}] - verify this fingerprint out of band.")
    print(f"opened -> {out}")
    if a.launch:
        if sys.platform == "win32":
            os.startfile(out)
        else:
            import subprocess
            subprocess.run(["open" if sys.platform == "darwin" else "xdg-open", str(out)])


def cmd_open(a):
    _apply_ca(a)
    recipient = load_identity(a.id, _passphrase(a.id))
    beacon = load_identity(a.beacon_key, _passphrase(a.beacon_key)) if a.beacon_key else None
    expected = load_public(a.sender) if a.sender else None
    header, _, _ = read_envelope(a.file)
    out = Path(a.output or header["filename"])
    _open_one(a, recipient, Path(a.file), out, beacon, expected, _location(a))


def cmd_receive(a):
    _apply_ca(a)
    me = load_identity(a.id, _passphrase(a.id))
    relay = RelayClient(a.server)
    files = relay.inbox(me)
    if a.file_id:
        files = [f for f in files if f["id"] in a.file_id]
    if not files:
        print("nothing to receive")
        return
    dest = Path(a.dir)
    dest.mkdir(parents=True, exist_ok=True)
    beacon = load_identity(a.beacon_key, _passphrase(a.beacon_key)) if a.beacon_key else None
    expected = load_public(a.sender) if a.sender else None
    loc = _location(a) if a.open else None
    for f in files:
        sealed = dest / f"{f['id']}_{f['filename']}.hig"
        relay.download(f["id"], sealed)
        print(f"received {sealed}  ({f['size']} B, from {f['sender']['name']})")
        if not a.open:
            continue
        try:
            _open_one(a, me, sealed, dest / f["filename"], beacon, expected, loc)
            if a.delete:
                relay.delete(me, f["id"])
        except (LTAError, OpenError) as e:
            print(f"    could not open: {e}")


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="higtlc", description="Hybrid Identity-Geographic Time-Locked Cryptosystem")
    sub = p.add_subparsers(dest="cmd", required=True)

    net = argparse.ArgumentParser(add_help=False)
    net.add_argument("--ca", help="CA certificate to trust for https:// (or set HIGTLC_CA)")

    opener = argparse.ArgumentParser(add_help=False)
    opener.add_argument("--sender", help="expected sender public identity (.pub)")
    opener.add_argument("--lat", type=float, help="override location (default: capture from device)")
    opener.add_argument("--lon", type=float)
    opener.add_argument("--accuracy", type=float, default=10.0, help="accuracy in metres with --lat/--lon")
    opener.add_argument("--beacon-key", help="SIMULATION: site beacon private identity to produce beacon proof")
    opener.add_argument("--dev-attestation", action="store_true", help="SIMULATION: send stub attestation")
    opener.add_argument("--lta", help="override LTA URL from the file header")
    opener.add_argument("--launch", action="store_true", help="open the decrypted file in its default app")

    s = sub.add_parser("keygen", help="create an identity (also used for site beacons)")
    s.add_argument("--name", required=True)
    s.add_argument("--out", required=True, help="private identity file, e.g. bob.id (writes bob.pub too)")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("fingerprint", help="show a public identity's fingerprint")
    s.add_argument("pub")
    s.set_defaults(fn=cmd_fingerprint)

    s = sub.add_parser("locate", help="show this device's current location")
    s.set_defaults(fn=cmd_locate)

    s = sub.add_parser("serve", help="run the server (Location-Time Authority + file relay)")
    s.add_argument("--state", default="lta_state", help="directory for server key, database and relayed files")
    s.add_argument("--host", default="127.0.0.1", help="0.0.0.0 to accept connections from other machines")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--tls-cert", help="server certificate (enables HTTPS)")
    s.add_argument("--tls-key", help="server private key")
    s.add_argument("--no-relay", action="store_true", help="run the LTA only")
    s.add_argument("--dev-attestation", action="store_true", help="accept stub attestations (testing only)")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("tls-cert", help="create a private CA + server certificate for HTTPS")
    s.add_argument("--host", action="append", required=True,
                   help="server IP or DNS name as clients will use it (repeatable)")
    s.add_argument("--out", default="certs")
    s.set_defaults(fn=cmd_tls_cert)

    s = sub.add_parser("seal", parents=[net], help="encrypt a file to a recipient + place + time window")
    s.add_argument("file")
    s.add_argument("--from", dest="sender", required=True, help="sender private identity (.id)")
    s.add_argument("--to", required=True, help="recipient public identity (.pub)")
    s.add_argument("--lta", required=True, help="server URL the RECEIVER can reach, e.g. https://192.168.1.5:8765")
    z = s.add_mutually_exclusive_group(required=True)
    z.add_argument("--circle", help="LAT,LON,RADIUS_M")
    z.add_argument("--polygon", help='"LAT,LON;LAT,LON;LAT,LON;..."')
    s.add_argument("--not-before", default="now", help="now | +2h | unix ts | ISO 8601 (default: now)")
    s.add_argument("--not-after", required=True, help="now | +2h | unix ts | ISO 8601")
    s.add_argument("--max-accuracy", type=float, default=25.0, help="max location error in metres (default 25)")
    s.add_argument("--beacon", help="site beacon public identity (.pub); requires on-site beacon proof")
    s.add_argument("--require-attestation", action="store_true")
    s.add_argument("--send", action="store_true", help="upload to the relay after sealing")
    s.add_argument("--relay", help="relay URL (default: same as --lta)")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_seal)

    s = sub.add_parser("send", parents=[net], help="upload a sealed .hig file to the relay")
    s.add_argument("file")
    s.add_argument("--server", required=True)
    s.set_defaults(fn=cmd_send)

    s = sub.add_parser("inspect", help="verify signature and show a sealed file's policy")
    s.add_argument("file")
    s.set_defaults(fn=cmd_inspect)

    s = sub.add_parser("inbox", parents=[net], help="list sealed files waiting for you on the relay")
    s.add_argument("--id", required=True, help="your private identity (.id)")
    s.add_argument("--server", required=True)
    s.set_defaults(fn=cmd_inbox)

    s = sub.add_parser("receive", parents=[net, opener], help="download files from the relay (and --open them)")
    s.add_argument("file_id", nargs="*", help="specific file ids (default: all in inbox)")
    s.add_argument("--id", required=True, help="your private identity (.id)")
    s.add_argument("--server", required=True)
    s.add_argument("--dir", default="received")
    s.add_argument("--open", action="store_true", help="decrypt after downloading")
    s.add_argument("--delete", action="store_true", help="remove from relay after a successful open")
    s.set_defaults(fn=cmd_receive)

    s = sub.add_parser("open", parents=[net, opener], help="decrypt a sealed file (needs LTA approval)")
    s.add_argument("file")
    s.add_argument("--id", required=True, help="recipient private identity (.id)")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_open)

    # Backwards-compatible alias: `higtlc lta serve`
    s = sub.add_parser("lta", help=argparse.SUPPRESS)
    lsub = s.add_subparsers(dest="lta_cmd", required=True)
    l = lsub.add_parser("serve")
    l.add_argument("--state", default="lta_state")
    l.add_argument("--host", default="127.0.0.1")
    l.add_argument("--port", type=int, default=8765)
    l.add_argument("--tls-cert")
    l.add_argument("--tls-key")
    l.add_argument("--no-relay", action="store_true")
    l.add_argument("--dev-attestation", action="store_true")
    l.set_defaults(fn=cmd_serve)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    from .location import LocationError
    try:
        a.fn(a)
    except (LTAError, OpenError, PolicyError, LocationError, ValueError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
