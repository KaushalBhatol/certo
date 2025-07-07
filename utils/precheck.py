import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import bcrypt
from utils.db import init_db, get_db

DATA_DIR = "data"
CERT_PATH = os.path.join(DATA_DIR, "ssl", "certo.crt")
KEY_PATH = os.path.join(DATA_DIR, "ssl", "certo.key")

def precheckes():
    os.makedirs(os.path.join(DATA_DIR, "rootca"), exist_ok=True)
    generate_self_signed_cert()
    initialize_user_store()

def initialize_user_store():
    init_db()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        print("⚠️ No users found. Creating default admin user...")
        password = "certo"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       ("certo", hashed, "admin"))
        conn.commit()
        print("✅ Default admin user created: certo / certo")

    conn.close()

def generate_self_signed_cert():
    if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH):
        ssl_dir = os.path.dirname(CERT_PATH)
        os.makedirs(ssl_dir, exist_ok=True)

        print("🔐 Generating self-signed SSL certificate...")

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

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

        with open(CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print(f"✅ SSL cert generated at {CERT_PATH} and key at {KEY_PATH}")
