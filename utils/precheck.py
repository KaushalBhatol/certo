import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import bcrypt
import json


DATA_DIR = "data"
USER_FILE = os.path.join(DATA_DIR, "user.json")
CERT_PATH = os.path.join(DATA_DIR, "ssl", "certo.crt")
KEY_PATH = os.path.join(DATA_DIR, "ssl", "certo.key")

def precheckes():
    # Creating Required Folder Structures
    os.makedirs(os.path.join(DATA_DIR, "rootca"), exist_ok=True)

    # Genrating SSL Certificates
    generate_self_signed_cert()

    # Creating User File
    initialize_user_store()

def initialize_user_store():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    if not os.path.exists(USER_FILE):
        print("⚠️  user.json not found. Creating default admin user...")

        default_password = "certo"
        password_hash = bcrypt.hashpw(default_password.encode(), bcrypt.gensalt()).decode()

        default_data = {
            "users": [
                {
                    "username": "certo",
                    "password_hash": password_hash,
                    "role": "admin"
                }
            ]
        }

        with open(USER_FILE, "w") as f:
            json.dump(default_data, f, indent=2)

        print(f"✅ Created `user.json` with default admin user.")
        print(f"   → Username: certo")
        print(f"   → Password: {default_password}")


def generate_self_signed_cert():
    if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH) :
        """Generate a self-signed SSL certificate using cryptography."""
        ssl_dir = os.path.dirname(CERT_PATH, )
        os.makedirs(ssl_dir, exist_ok=True)

        print("🔐 Generating self-signed SSL certificate...")

        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SelfSigned"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Certo"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
            .sign(key, hashes.SHA256())

        # Write key and cert to files
        with open(CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print(f"✅ SSL certificate created at:")
        print(f"   → Certificate: {CERT_PATH}")
        print(f"   → Key:         {KEY_PATH}")
