import os
import json
import bcrypt
import zipfile
import io
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, redirect, url_for, render_template, session, flash, send_file
from werkzeug.utils import secure_filename
import pycountry

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from utils.precheck import precheckes, CERT_PATH, KEY_PATH, USER_FILE

# Prechecks
precheckes()

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.before_request
def redirect_http_to_https():
    if not request.is_secure and not app.debug and not request.host.startswith("localhost"):
        return redirect(request.url.replace("http://", "https://", 1), code=301)

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

        with open(USER_FILE, "r") as f:
            users = json.load(f)["users"]

        user = next((u for u in users if u["username"] == username), None)
        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            session["username"] = username
            session["role"] = user["role"]
            return redirect(url_for("home"))

        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

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

    cert_file_path = os.path.join("data", "cert.json")
    certs = {"root_cas": []}
    if os.path.exists(cert_file_path):
        with open(cert_file_path, "r") as f:
            certs = json.load(f)

    certs["root_cas"].append({
        "name": name,
        "path": save_dir
    })

    with open(cert_file_path, "w") as f:
        json.dump(certs, f, indent=2)

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

    cert_file_path = os.path.join("data", "cert.json")
    certs = {"root_cas": []}
    if os.path.exists(cert_file_path):
        with open(cert_file_path, "r") as f:
            certs = json.load(f)

    certs["root_cas"].append({
        "name": name,
        "path": save_dir
    })

    with open(cert_file_path, "w") as f:
        json.dump(certs, f, indent=2)

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
    certs = []
    cert_file_path = os.path.join("data", "cert.json")
    countries = sorted([(c.alpha_2, c.name) for c in pycountry.countries])

    if os.path.exists(cert_file_path):
        with open(cert_file_path, "r") as f:
            raw = json.load(f).get("root_cas", [])
        for cert in raw:
            cert_path = os.path.join(cert["path"], "cert.pem")
            if os.path.exists(cert_path):
                with open(cert_path, "rb") as cf:
                    cert_data = x509.load_pem_x509_certificate(cf.read())
                    created = cert_data.not_valid_before_utc.strftime("%Y-%m-%d")
                    expires = cert_data.not_valid_after_utc.strftime("%Y-%m-%d")
                    certs.append({**cert, "created": created, "expires": expires})
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

    cert_file_path = os.path.join("data", "cert.json")
    if os.path.exists(cert_file_path):
        with open(cert_file_path, "r") as f:
            certs = json.load(f)
        certs["root_cas"] = [c for c in certs.get("root_cas", []) if c["name"] != name]
        with open(cert_file_path, "w") as f:
            json.dump(certs, f, indent=2)

    flash(f"Deleted Root CA: {name}")
    return redirect(url_for("rootca"))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080, ssl_context=(CERT_PATH, KEY_PATH))
