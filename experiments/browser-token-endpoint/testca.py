#!/usr/bin/env python3
"""Test CA standing in for Let's Encrypt in the experiment.

  testca.py init DIR                       create CA key + cert (DIR/ca.pem)
  testca.py issue DIR SPKI_B64 DNSNAME     print leaf cert (DER, base64) for that public key
  testca.py verify-csr CSR_B64             check a CSR's signature and print its subject/SAN
"""
import base64, datetime, json, os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def init(d):
    os.makedirs(d, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Experiment Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    open(f"{d}/ca.key", "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(f"{d}/ca.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"{d}/ca.pem")

def issue(d, spki_b64, dns):
    ca_key = serialization.load_pem_private_key(open(f"{d}/ca.key", "rb").read(), None)
    ca = x509.load_pem_x509_certificate(open(f"{d}/ca.pem", "rb").read())
    pub = serialization.load_der_public_key(base64.b64decode(spki_b64))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)]))
            .issuer_name(ca.subject).public_key(pub).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .sign(ca_key, hashes.SHA256()))
    print(base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode())

def verify_csr(csr_b64):
    csr = x509.load_der_x509_csr(base64.b64decode(csr_b64))
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    print(json.dumps({"signature_valid": csr.is_signature_valid, "subject": csr.subject.rfc4514_string(), "san": san,
                      "public_key": base64.b64encode(csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()}))

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "init": init(sys.argv[2])
    elif cmd == "issue": issue(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "verify-csr": verify_csr(sys.argv[2])
