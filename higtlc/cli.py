"""Command-line interface: higtlc keygen | seal | open | inspect | lta serve."""
import argparse
import getpass
import os
import sys
from pathlib import Path

from .container import Location, OpenError, open_file, read_envelope, seal_file, verify_header
from .keys import Identity, load_identity, load_public, save_identity, save_public
from .lta_client import LTAClient, LTAError
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


def _zone(a) -> dict:
    if a.circle:
        lat, lon, r = (float(x) for x in a.circle.split(","))
        return circle_zone(lat, lon, r)
    pts = [tuple(float(x) for x in p.split(",")) for p in a.polygon.split(";") if p.strip()]
    return polygon_zone(pts)


def cmd_seal(a):
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
    print(f"sealed -> {out}")
    print(f"  recipient: {recipient.name} [{recipient.fingerprint}]")
    print(f"  zone:      {describe_zone(policy['zone'])}")
    print(f"  window:    {fmt_time(policy['not_before'])}  ->  {fmt_time(policy['not_after'])}")


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


def cmd_open(a):
    recipient = load_identity(a.id, _passphrase(a.id))
    beacon = load_identity(a.beacon_key, _passphrase(a.beacon_key)) if a.beacon_key else None
    expected = load_public(a.sender) if a.sender else None
    header, _, _ = read_envelope(a.file)
    out = a.output or header["filename"]
    lta = LTAClient(a.lta) if a.lta else None
    header = open_file(a.file, out, recipient=recipient, location=Location(a.lat, a.lon, a.accuracy),
                       lta=lta, expected_sender=expected, beacon=beacon, dev_attestation=a.dev_attestation)
    if expected is None:
        print(f"WARNING: sender not pinned. Signed by {header['sender']['name']} "
              f"[{header['sender']['fingerprint']}] - verify this fingerprint out of band.")
    print(f"opened -> {out}")


def cmd_lta_serve(a):
    import uvicorn
    from .lta_server import create_app
    if a.dev_attestation:
        print("WARNING: --dev-attestation accepts stub attestations. Never use in production.")
    uvicorn.run(create_app(a.state, dev_attestation=a.dev_attestation), host=a.host, port=a.port)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="higtlc", description="Hybrid Identity-Geographic Time-Locked Cryptosystem")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create an identity (also used for site beacons)")
    s.add_argument("--name", required=True)
    s.add_argument("--out", required=True, help="private identity file, e.g. bob.id (writes bob.pub too)")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("fingerprint", help="show a public identity's fingerprint")
    s.add_argument("pub")
    s.set_defaults(fn=cmd_fingerprint)

    s = sub.add_parser("seal", help="encrypt a file to a recipient + place + time window")
    s.add_argument("file")
    s.add_argument("--from", dest="sender", required=True, help="sender private identity (.id)")
    s.add_argument("--to", required=True, help="recipient public identity (.pub)")
    s.add_argument("--lta", required=True, help="LTA base URL, e.g. http://127.0.0.1:8765")
    z = s.add_mutually_exclusive_group(required=True)
    z.add_argument("--circle", help="LAT,LON,RADIUS_M")
    z.add_argument("--polygon", help='"LAT,LON;LAT,LON;LAT,LON;..."')
    s.add_argument("--not-before", default="now", help="now | +2h | unix ts | ISO 8601 (default: now)")
    s.add_argument("--not-after", required=True, help="now | +2h | unix ts | ISO 8601")
    s.add_argument("--max-accuracy", type=float, default=25.0, help="max GPS error in metres (default 25)")
    s.add_argument("--beacon", help="site beacon public identity (.pub); requires on-site beacon proof")
    s.add_argument("--require-attestation", action="store_true")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_seal)

    s = sub.add_parser("inspect", help="verify signature and show a sealed file's policy")
    s.add_argument("file")
    s.set_defaults(fn=cmd_inspect)

    s = sub.add_parser("open", help="decrypt a sealed file (needs LTA approval)")
    s.add_argument("file")
    s.add_argument("--id", required=True, help="recipient private identity (.id)")
    s.add_argument("--sender", help="expected sender public identity (.pub)")
    s.add_argument("--lat", type=float, required=True)
    s.add_argument("--lon", type=float, required=True)
    s.add_argument("--accuracy", type=float, default=10.0, help="GPS accuracy in metres (default 10)")
    s.add_argument("--beacon-key", help="SIMULATION: site beacon private identity to produce beacon proof")
    s.add_argument("--dev-attestation", action="store_true", help="SIMULATION: send stub attestation")
    s.add_argument("--lta", help="override LTA URL from the file header")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_open)

    s = sub.add_parser("lta", help="Location-Time Authority")
    lsub = s.add_subparsers(dest="lta_cmd", required=True)
    l = lsub.add_parser("serve")
    l.add_argument("--state", default="lta_state", help="directory for LTA key + database")
    l.add_argument("--host", default="127.0.0.1")
    l.add_argument("--port", type=int, default=8765)
    l.add_argument("--dev-attestation", action="store_true", help="accept stub attestations (testing only)")
    l.set_defaults(fn=cmd_lta_serve)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        a.fn(a)
    except (LTAError, OpenError, PolicyError, ValueError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
