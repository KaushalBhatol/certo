import os
import io
import bcrypt
import zipfile
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, redirect, url_for, render_template, session, flash, send_file
from werkzeug.utils import secure_filename
import pycountry

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from utils.precheck import precheckes, CERT_PATH, KEY_PATH
from utils.db import get_db

# Prechecks
precheckes()

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.before_request
def redirect_http_to_https():
    if not request.is_secure and not app.debug and not request.host.startswith("localhost"):
        return redirect(request.url.replace("http://", "https://", 1), code=301)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session or session.get("role") != "admin":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("home"))

        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- ROOT CA ROUTES ----------

@app.route("/rootca/import", methods=["POST"])
@admin_required
def import_rootca():
    cert = request.files.get("cert")
    key = request.files.get("key")
    name = request.form.get("name")

    if not cert or not key or not name:
        flash("Missing certificate, key, or name")
        return redirect(url_for("rootca"))

    safe_name = secure_filename(name)
    save_dir = os.path.join("data", "rootca", safe_name)
    os.makedirs(save_dir, exist_ok=True)

    cert_path = os.path.join(save_dir, "cert.pem")
    key_path = os.path.join(save_dir, "key.pem")

    cert.save(cert_path)
    key.save(key_path)

    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO root_cas (name, path) VALUES (?, ?)", (name, save_dir))
    conn.commit()
    conn.close()

    flash("Certificate imported")
    return redirect(url_for("rootca"))

@app.route("/rootca/create", methods=["POST"])
@admin_required
def create_rootca():
    name = request.form.get("name")
    country = request.form.get("country", "US")
    org = request.form.get("org", "Certo")
    common_name = request.form.get("common_name", "localhost")
    days = int(request.form.get("days") or 365)

    if not name:
        flash("Name required")
        return redirect(url_for("rootca"))

    save_dir = os.path.join("data", "rootca", secure_filename(name))
    os.makedirs(save_dir, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(key, hashes.SHA256())

    cert_path = os.path.join(save_dir, "cert.pem")
    key_path = os.path.join(save_dir, "key.pem")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO root_cas (name, path) VALUES (?, ?)", (name, save_dir))
    conn.commit()
    conn.close()

    flash("New Root CA created")
    return redirect(url_for("rootca"))

@app.route("/rootca/reissue/<name>", methods=["POST"])
@admin_required
def reissue_rootca(name):
    safe_name = secure_filename(name)
    ca_dir = os.path.join("data", "rootca", safe_name)
    key_path = os.path.join(ca_dir, "key.pem")
    cert_path = os.path.join(ca_dir, "cert.pem")
    days = int(request.form.get("days") or 365)

    if not os.path.exists(key_path):
        flash("Private key not found. Cannot reissue.")
        return redirect(url_for("rootca"))

    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    cert = x509.CertificateBuilder() \
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Reissued Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])) \
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Reissued Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(key, hashes.SHA256())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    flash(f"Certificate for {name} reissued successfully")
    return redirect(url_for("rootca"))

@app.route("/rootca", methods=["GET"])
@admin_required
def rootca():
    countries = sorted([(c.alpha_2, c.name) for c in pycountry.countries])
    certs = []

    conn = get_db()
    rows = conn.execute("SELECT * FROM root_cas").fetchall()
    conn.close()

    for cert in rows:
        cert_path = os.path.join(cert["path"], "cert.pem")
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert_data = x509.load_pem_x509_certificate(f.read())
                certs.append({
                    "name": cert["name"],
                    "path": cert["path"],
                    "created": cert_data.not_valid_before_utc.strftime("%Y-%m-%d"),
                    "expires": cert_data.not_valid_after_utc.strftime("%Y-%m-%d")
                })

    return render_template("rootca.html", certs=certs, countries=countries)

@app.route("/rootca/export/<name>")
@admin_required
def export_cert(name):
    safe_name = secure_filename(name)
    ca_dir = os.path.join("data", "rootca", safe_name)
    cert_path = os.path.join(ca_dir, "cert.pem")
    key_path = os.path.join(ca_dir, "key.pem")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        flash("Certificate files not found")
        return redirect(url_for("rootca"))

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zipf:
        zipf.write(cert_path, arcname=f"{name}_cert.pem")
        zipf.write(key_path, arcname=f"{name}_key.pem")
    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{name}_rootca.zip"
    )

@app.route("/rootca/delete", methods=["POST"])
@admin_required
def delete_rootca():
    name = request.form.get("name")
    confirm_name = request.form.get("confirm_name")

    if name != confirm_name:
        flash("Name confirmation mismatch. Deletion cancelled.")
        return redirect(url_for("rootca"))

    path = os.path.join("data", "rootca", secure_filename(name))
    if os.path.exists(path):
        import shutil
        shutil.rmtree(path)

    conn = get_db()
    conn.execute("DELETE FROM root_cas WHERE name = ?", (name,))
    conn.commit()
    conn.close()

    flash(f"Deleted Root CA: {name}")
    return redirect(url_for("rootca"))

# ---------- SSL CERTIFICATE ROUTES ----------

@app.route("/ssl", methods=["GET"])
@login_required
def ssl_page():
    conn = get_db()
    rows = conn.execute("SELECT * FROM root_cas").fetchall()
    conn.close()

    countries = sorted([(c.alpha_2, c.name) for c in pycountry.countries])
    rootcas = [dict(name=row["name"]) for row in rows]
    certs = []

    ssl_dir = os.path.join("data", "ssl")
    if os.path.exists(ssl_dir):
        for name in os.listdir(ssl_dir):
            folder = os.path.join(ssl_dir, name)
            cert_path = os.path.join(folder, "cert.pem")
            meta_path = os.path.join(folder, "meta.txt")

            if os.path.exists(cert_path):
                with open(cert_path, "rb") as f:
                    cert_obj = x509.load_pem_x509_certificate(f.read())

                root_ca_name = None
                if os.path.exists(meta_path):
                    with open(meta_path, "r") as f:
                        root_ca_name = f.read().strip()

                certs.append({
                    "name": name,
                    "created": cert_obj.not_valid_before_utc.strftime("%Y-%m-%d"),
                    "expires": cert_obj.not_valid_after_utc.strftime("%Y-%m-%d"),
                    "root_ca": root_ca_name or "Unknown"
                })

    return render_template("ssl.html", rootcas=rootcas, countries=countries, certs=certs)

@app.route("/ssl/create", methods=["POST"])
@login_required
def create_ssl():
    name = request.form.get("name")
    common_name = request.form.get("common_name")
    org = request.form.get("org")
    country = request.form.get("country", "US")
    days = int(request.form.get("days") or 365)
    selected_ca = request.form.get("root_ca")

    if not all([name, common_name, org, selected_ca]):
        flash("All fields are required.")
        return redirect(url_for("ssl_page"))

    ca_dir = os.path.join("data", "rootca", secure_filename(selected_ca))
    ssl_dir = os.path.join("data", "ssl", secure_filename(name))
    os.makedirs(ssl_dir, exist_ok=True)

    ca_cert_path = os.path.join(ca_dir, "cert.pem")
    ca_key_path = os.path.join(ca_dir, "key.pem")

    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        flash("Selected Root CA not found.")
        return redirect(url_for("ssl_page"))

    # Load CA certificate and key
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Generate private key
    ssl_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build subject name
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Build certificate
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(ca_cert.subject) \
        .public_key(ssl_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .sign(ca_key, hashes.SHA256())

    # Write cert.pem
    cert_path = os.path.join(ssl_dir, "cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write key.pem
    key_path = os.path.join(ssl_dir, "key.pem")
    with open(key_path, "wb") as f:
        f.write(ssl_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write fullchain.pem (cert + CA cert)
    fullchain_path = os.path.join(ssl_dir, "fullchain.pem")
    with open(fullchain_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # Save Root CA name used for signing
    meta_path = os.path.join(ssl_dir, "meta.txt")
    with open(meta_path, "w") as f:
        f.write(selected_ca)

    flash(f"SSL certificate '{name}' created successfully.")
    return redirect(url_for("ssl_page"))


@app.route("/ssl/export/<name>")
@login_required
def export_ssl(name):
    safe_name = secure_filename(name)
    ssl_dir = os.path.join("data", "ssl", safe_name)

    cert_path = os.path.join(ssl_dir, "cert.pem")
    key_path = os.path.join(ssl_dir, "key.pem")
    fullchain_path = os.path.join(ssl_dir, "fullchain.pem")
    meta_path = os.path.join(ssl_dir, "meta.txt")

    # Check if any of the critical files are missing
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        flash("SSL certificate files not found.")
        return redirect(url_for("ssl_page"))

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zipf:
        zipf.write(cert_path, arcname=f"{name}_cert.pem")
        zipf.write(key_path, arcname=f"{name}_key.pem")

        if os.path.exists(fullchain_path):
            zipf.write(fullchain_path, arcname=f"{name}_fullchain.pem")

        if os.path.exists(meta_path):
            zipf.write(meta_path, arcname=f"{name}_meta.txt")

    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{name}_ssl_export.zip"
    )

@app.route("/ssl/reissue/<name>", methods=["POST"])
@login_required
def reissue_ssl(name):
    safe_name = secure_filename(name)
    ssl_dir = os.path.join("data", "ssl", safe_name)
    days = int(request.form.get("days") or 365)

    key_path = os.path.join(ssl_dir, "key.pem")
    cert_path = os.path.join(ssl_dir, "cert.pem")
    meta_path = os.path.join(ssl_dir, "meta.txt")

    if not all([os.path.exists(p) for p in [key_path, meta_path]]):
        flash("Missing key or meta information.")
        return redirect(url_for("ssl_page"))

    with open(key_path, "rb") as f:
        ssl_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(meta_path, "r") as f:
        root_ca = f.read().strip()

    ca_dir = os.path.join("data", "rootca", secure_filename(root_ca))
    ca_cert_path = os.path.join(ca_dir, "cert.pem")
    ca_key_path = os.path.join(ca_dir, "key.pem")

    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        flash("Root CA used for signing not found.")
        return redirect(url_for("ssl_page"))

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Create new cert
    cert = x509.CertificateBuilder() \
        .subject_name(ca_cert.subject) \
        .issuer_name(ca_cert.subject) \
        .public_key(ssl_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .sign(ca_key, hashes.SHA256())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    flash(f"Reissued SSL certificate '{name}' successfully.")
    return redirect(url_for("ssl_page"))

@app.route("/ssl/delete", methods=["POST"])
@login_required
def delete_ssl():
    name = request.form.get("name")
    confirm_name = request.form.get("confirm_name")

    if name != confirm_name:
        flash("Confirmation name does not match.")
        return redirect(url_for("ssl_page"))

    ssl_path = os.path.join("data", "ssl", secure_filename(name))
    if os.path.exists(ssl_path):
        import shutil
        shutil.rmtree(ssl_path)
        flash(f"Deleted SSL certificate: {name}")
    else:
        flash("SSL certificate not found.")

    return redirect(url_for("ssl_page"))

@app.route("/ssl/import", methods=["POST"])
@login_required
def import_ssl():
    name = request.form.get("name")
    root_ca = request.form.get("root_ca")
    cert = request.files.get("cert")
    key = request.files.get("key")

    if not all([name, root_ca, cert, key]):
        flash("All fields are required.")
        return redirect(url_for("ssl_page"))

    save_dir = os.path.join("data", "ssl", secure_filename(name))
    os.makedirs(save_dir, exist_ok=True)

    cert.save(os.path.join(save_dir, "cert.pem"))
    key.save(os.path.join(save_dir, "key.pem"))

    with open(os.path.join(save_dir, "meta.txt"), "w") as f:
        f.write(root_ca)

    flash(f"SSL certificate '{name}' imported.")
    return redirect(url_for("ssl_page"))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080, ssl_context=(CERT_PATH, KEY_PATH))
