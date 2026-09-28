"""Generate a private CA + server certificate so the server can run over HTTPS.

Give ca.crt to every client (--ca ca.crt or $HIGTLC_CA); keep server.key on the server.
"""
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _san(hosts: list[str]) -> x509.SubjectAlternativeName:
    entries = []
    for h in hosts:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            entries.append(x509.DNSName(h))
    return x509.SubjectAlternativeName(entries)


def generate(hosts: list[str], out_dir: str | Path, days: int = 365) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (x509.CertificateBuilder()
               .subject_name(_name("HIG-TLC private CA")).issuer_name(_name("HIG-TLC private CA"))
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                            content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))

    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_cert = (x509.CertificateBuilder()
                .subject_name(_name(hosts[0])).issuer_name(ca_cert.subject)
                .public_key(srv_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
                .add_extension(_san(hosts), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                # Python 3.13+ verifies with VERIFY_X509_STRICT, which requires key identifiers.
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                               critical=False)
                .sign(ca_key, hashes.SHA256()))

    pem = serialization.Encoding.PEM
    no_enc = serialization.NoEncryption()
    pkcs8 = serialization.PrivateFormat.PKCS8
    paths = {"ca": out / "ca.crt", "cert": out / "server.crt", "key": out / "server.key"}
    paths["ca"].write_bytes(ca_cert.public_bytes(pem))
    paths["cert"].write_bytes(srv_cert.public_bytes(pem))
    paths["key"].write_bytes(srv_key.private_bytes(pem, pkcs8, no_enc))
    return paths
