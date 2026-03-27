import os
import io
import base64
import secrets
import bcrypt
import pyotp
import qrcode
import zipfile
from functools import wraps
from datetime import datetime, timedelta, timezone
import ipaddress as _ipaddress
from flask import Flask, request, redirect, url_for, render_template, session, flash, send_file
from werkzeug.utils import secure_filename
import pycountry

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from utils.precheck import precheckes, CERT_PATH, KEY_PATH
from utils.db import get_db

# Prechecks
precheckes()

app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    import warnings
    warnings.warn("SECRET_KEY env var not set — using a random key. Sessions will not survive restarts.")
    _secret = os.urandom(24)
app.secret_key = _secret
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year in seconds

@app.context_processor
def inject_branding():
    conn = get_db()
    row = conn.execute("SELECT * FROM branding WHERE id = 1").fetchone()
    conn.close()
    return {"branding": row}

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
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Access denied. Admin privileges required.", "error")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated

def _get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

def _audit_log(action, target="", details=""):
    """Write one audit log entry and purge records older than 3 months."""
    username = session.get("username", "anonymous")
    ip = _get_ip()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (timestamp, username, ip_address, action, target, details) VALUES (?,?,?,?,?,?)",
        (now, username, ip, action, target, details)
    )
    # Keep only last 3 months
    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S UTC")
    conn.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()

def _cert_details(cert_obj):
    """Return a dict of human-readable fields from an x509 cert object."""
    def attr(name_obj, oid):
        a = name_obj.get_attributes_for_oid(oid)
        return a[0].value if a else ""

    # SANs
    sans = []
    try:
        san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for n in san_ext.value:
            sans.append(str(n.value))
    except x509.ExtensionNotFound:
        pass

    # Key usage
    key_usage = []
    try:
        ku = cert_obj.extensions.get_extension_for_class(x509.KeyUsage).value
        for flag in ["digital_signature","content_commitment","key_encipherment",
                     "data_encipherment","key_agreement","key_cert_sign","crl_sign"]:
            if getattr(ku, flag):
                key_usage.append(flag.replace("_", " ").title())
    except x509.ExtensionNotFound:
        pass

    # Extended key usage
    eku = []
    try:
        for oid in cert_obj.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            eku.append(oid._name if hasattr(oid, '_name') else oid.dotted_string)
    except x509.ExtensionNotFound:
        pass

    pub = cert_obj.public_key()
    key_size = pub.key_size if hasattr(pub, "key_size") else "—"

    return {
        "cn":       attr(cert_obj.subject, NameOID.COMMON_NAME),
        "o":        attr(cert_obj.subject, NameOID.ORGANIZATION_NAME),
        "ou":       attr(cert_obj.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "c":        attr(cert_obj.subject, NameOID.COUNTRY_NAME),
        "st":       attr(cert_obj.subject, NameOID.STATE_OR_PROVINCE_NAME),
        "l":        attr(cert_obj.subject, NameOID.LOCALITY_NAME),
        "issuer_cn": attr(cert_obj.issuer, NameOID.COMMON_NAME),
        "issuer_o":  attr(cert_obj.issuer, NameOID.ORGANIZATION_NAME),
        "serial":   format(cert_obj.serial_number, "x").upper(),
        "not_before": cert_obj.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "not_after":  cert_obj.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "key_size": key_size,
        "algorithm": "RSA",
        "sans":     sans,
        "key_usage": key_usage,
        "eku":      eku,
    }

def _days_until(expiry_date_str, fallback=365):
    """Convert a YYYY-MM-DD expiry date string to days from now."""
    try:
        exp = datetime.strptime(expiry_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return max(1, (exp - datetime.now(timezone.utc)).days)
    except (ValueError, TypeError):
        return fallback

@app.route("/")
@login_required
def home():
    conn = get_db()
    ca_rows = conn.execute("SELECT * FROM root_cas").fetchall()
    conn.close()

    ca_count = len(ca_rows)
    ssl_count = 0
    expiring = []
    now = datetime.now(timezone.utc)
    warn_threshold = now + timedelta(days=30)

    # Count SSL certs and find expiring ones
    ssl_dir = os.path.join("data", "ssl")
    if os.path.exists(ssl_dir):
        for entry in os.listdir(ssl_dir):
            cert_path = os.path.join(ssl_dir, entry, "cert.pem")
            if not os.path.exists(cert_path):
                continue
            ssl_count += 1
            with open(cert_path, "rb") as f:
                c = x509.load_pem_x509_certificate(f.read())
            if c.not_valid_after_utc <= warn_threshold:
                expiring.append({
                    "name": entry, "type": "SSL",
                    "expires": c.not_valid_after_utc.strftime("%Y-%m-%d"),
                    "expired": c.not_valid_after_utc <= now,
                })

    # Check Root CA expiry too
    for row in ca_rows:
        cert_path = os.path.join(row["path"], "cert.pem")
        if not os.path.exists(cert_path):
            continue
        with open(cert_path, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        if c.not_valid_after_utc <= warn_threshold:
            expiring.append({
                "name": row["name"], "type": "Root CA",
                "expires": c.not_valid_after_utc.strftime("%Y-%m-%d"),
                "expired": c.not_valid_after_utc <= now,
            })

    expiring.sort(key=lambda x: x["expires"])

    return render_template("home.html",
        ca_count=ca_count, ssl_count=ssl_count, expiring=expiring)

@app.route("/login", methods=["GET", "POST"])
def login():
    username = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            if not user["enabled"]:
                flash("Your account has been disabled. Contact an administrator.", "error")
                return render_template("login.html", username=username)
            if user["mfa_enabled"]:
                session["mfa_pending_username"] = user["username"]
                session["mfa_pending_role"] = user["role"]
                return redirect(url_for("mfa_verify"))
            session["username"] = user["username"]
            session["role"] = user["role"]
            _audit_log("Login Success", target=user["username"])
            return redirect(url_for("home"))

        # Log password failure (username may not exist — log the attempted username)
        ip = _get_ip()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        conn2 = get_db()
        conn2.execute(
            "INSERT INTO audit_logs (timestamp, username, ip_address, action, target, details) VALUES (?,?,?,?,?,?)",
            (now, username or "unknown", ip, "Password Authentication Failed", "", "")
        )
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S UTC")
        conn2.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
        conn2.commit()
        conn2.close()
        flash("Invalid credentials", "error")
    return render_template("login.html", username=username)

@app.route("/logout")
@login_required
def logout():
    _audit_log("Logout")
    session.clear()
    return redirect(url_for("login"))

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        conn.execute("UPDATE users SET full_name = ?, email = ? WHERE username = ?",
                     (full_name, email, session["username"]))

        if current_password or new_password or confirm_password:
            if not bcrypt.checkpw(current_password.encode(), user["password_hash"].encode()):
                conn.commit()
                conn.close()
                flash("Current password is incorrect.", "error")
                return redirect(url_for("settings"))
            if new_password != confirm_password:
                conn.commit()
                conn.close()
                flash("New passwords do not match.", "error")
                return redirect(url_for("settings"))
            if len(new_password) < 4:
                conn.commit()
                conn.close()
                flash("New password must be at least 4 characters.", "error")
                return redirect(url_for("settings"))
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                         (hashed, session["username"]))
            conn.commit()
            conn.close()
            _audit_log("Password Changed")
            flash("Settings saved.", "success")
            return redirect(url_for("settings"))

        conn.commit()
        conn.close()
        _audit_log("Profile Updated")
        flash("Settings saved.", "success")
        return redirect(url_for("settings"))

    conn.close()
    return render_template("settings.html", user=user)

# ---------- MFA ROUTES ----------

@app.route("/mfa", methods=["GET", "POST"])
def mfa_verify():
    if "mfa_pending_username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace("-", "").replace(" ", "")
        username = session["mfa_pending_username"]

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # Try TOTP
        totp = pyotp.TOTP(user["mfa_secret"])
        if totp.verify(code, valid_window=1):
            conn.close()
            session.pop("mfa_pending_username")
            session.pop("mfa_pending_role")
            session["username"] = user["username"]
            session["role"] = user["role"]
            _audit_log("Login Success", target=user["username"], details="MFA verified")
            return redirect(url_for("home"))

        # Try backup code
        backup = conn.execute(
            "SELECT * FROM backup_codes WHERE username = ? AND used = 0", (username,)
        ).fetchall()
        for row in backup:
            if bcrypt.checkpw(code.encode(), row["code_hash"].encode()):
                conn.execute("UPDATE backup_codes SET used = 1 WHERE id = ?", (row["id"],))
                conn.commit()
                conn.close()
                session.pop("mfa_pending_username")
                session.pop("mfa_pending_role")
                session["username"] = user["username"]
                session["role"] = user["role"]
                _audit_log("Login Success", target=user["username"], details="MFA backup code used")
                flash("Backup code used. Please generate new backup codes.", "warning")
                return redirect(url_for("home"))

        conn.close()
        ip = _get_ip()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        conn2 = get_db()
        conn2.execute(
            "INSERT INTO audit_logs (timestamp, username, ip_address, action, target, details) VALUES (?,?,?,?,?,?)",
            (now, username, ip, "MFA Authentication Failed", "", "")
        )
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S UTC")
        conn2.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
        conn2.commit()
        conn2.close()
        flash("Invalid code. Please try again.", "error")

    return render_template("mfa_verify.html")


@app.route("/settings/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("mfa_setup_secret")

        if not secret:
            return redirect(url_for("mfa_setup"))

        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            flash("Invalid code. Please scan the QR code again and try.", "error")
            return redirect(url_for("mfa_setup"))

        # Generate 8 backup codes
        plain_codes = [
            f"{secrets.token_hex(3).upper()}-{secrets.token_hex(3).upper()}"
            for _ in range(8)
        ]

        conn = get_db()
        conn.execute("UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE username = ?",
                     (secret, session["username"]))
        conn.execute("DELETE FROM backup_codes WHERE username = ?", (session["username"],))
        for code_plain in plain_codes:
            code_hash = bcrypt.hashpw(code_plain.replace("-", "").encode(), bcrypt.gensalt()).decode()
            conn.execute("INSERT INTO backup_codes (username, code_hash) VALUES (?, ?)",
                         (session["username"], code_hash))
        conn.commit()
        conn.close()

        session.pop("mfa_setup_secret", None)
        session["mfa_backup_codes"] = plain_codes
        _audit_log("MFA Enabled")
        return redirect(url_for("mfa_backup_codes"))

    # Generate a fresh secret for setup
    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=session["username"], issuer_name="Certo")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("mfa_setup.html", qr_b64=qr_b64, secret=secret)


@app.route("/settings/mfa/backup-codes")
@login_required
def mfa_backup_codes():
    codes = session.pop("mfa_backup_codes", None)
    if not codes:
        return redirect(url_for("settings"))
    return render_template("mfa_backup_codes.html", codes=codes)


@app.route("/settings/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    password = request.form.get("password", "")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()

    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        conn.close()
        flash("Incorrect password. MFA was not disabled.", "error")
        return redirect(url_for("settings"))

    conn.execute("UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE username = ?",
                 (session["username"],))
    conn.execute("DELETE FROM backup_codes WHERE username = ?", (session["username"],))
    conn.commit()
    conn.close()
    _audit_log("MFA Disabled")
    flash("MFA has been disabled.", "success")
    return redirect(url_for("settings"))


# ---------- ROOT CA ROUTES ----------

@app.route("/rootca/import", methods=["POST"])
@admin_required
def import_rootca():
    cert = request.files.get("cert")
    key = request.files.get("key")
    name = request.form.get("name")

    if not cert or not key or not name:
        flash("Missing certificate, key, or name", "error")
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

    _audit_log("Imported Root CA", target=name)
    flash("Certificate imported", "success")
    return redirect(url_for("rootca"))

@app.route("/rootca/create", methods=["POST"])
@admin_required
def create_rootca():
    name = request.form.get("name")
    country = request.form.get("country", "US")
    state = request.form.get("state", "").strip()
    locality = request.form.get("locality", "").strip()
    org = request.form.get("org", "Certo")
    ou = request.form.get("ou", "").strip()
    common_name = request.form.get("common_name", "localhost")
    days = _days_until(request.form.get("expiry_date"), fallback=1825)

    if not name:
        flash("Name required", "error")
        return redirect(url_for("rootca"))

    save_dir = os.path.join("data", "rootca", secure_filename(name))
    os.makedirs(save_dir, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name_attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, country)]
    if state:
        name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    subject = issuer = x509.Name(name_attrs)

    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False
        ), critical=True) \
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False) \
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

    _audit_log("Created Root CA", target=name)
    flash("New Root CA created", "success")
    return redirect(url_for("rootca"))

@app.route("/rootca/reissue/<name>", methods=["POST"])
@admin_required
def reissue_rootca(name):
    safe_name = secure_filename(name)
    ca_dir = os.path.join("data", "rootca", safe_name)
    key_path = os.path.join(ca_dir, "key.pem")
    cert_path = os.path.join(ca_dir, "cert.pem")
    days = _days_until(request.form.get("expiry_date"), fallback=1825)

    if not os.path.exists(key_path):
        flash("Private key not found. Cannot reissue.", "error")
        return redirect(url_for("rootca"))

    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    with open(cert_path, "rb") as f:
        existing_cert = x509.load_pem_x509_certificate(f.read())

    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(existing_cert.subject) \
        .issuer_name(existing_cert.subject) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False
        ), critical=True) \
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False) \
        .sign(key, hashes.SHA256())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    _audit_log("Reissued Root CA", target=name)
    flash(f"Certificate for {name} reissued successfully", "success")
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
            details = _cert_details(cert_data)
            certs.append({
                "name": cert["name"],
                "path": cert["path"],
                "created": cert_data.not_valid_before_utc.strftime("%Y-%m-%d"),
                "expires": cert_data.not_valid_after_utc.strftime("%Y-%m-%d"),
                "details": details,
            })

    return render_template("rootca.html", certs=certs, countries=countries)

@app.route("/rootca/view/<name>")
@admin_required
def view_rootca(name):
    safe_name = secure_filename(name)
    ca_dir = os.path.join("data", "rootca", safe_name)
    cert_path = os.path.join(ca_dir, "cert.pem")
    key_path  = os.path.join(ca_dir, "key.pem")
    if not os.path.exists(cert_path):
        flash("Certificate not found.", "error")
        return redirect(url_for("rootca"))
    with open(cert_path, "rb") as f:
        cert_obj = x509.load_pem_x509_certificate(f.read())
    details = _cert_details(cert_obj)
    pem_files = {"Certificate": open(cert_path).read()}
    if os.path.exists(key_path):
        pem_files["Private Key"] = open(key_path).read()
    _audit_log("Viewed Root CA", target=name, details=", ".join(pem_files.keys()))
    return render_template("cert_detail.html", name=name, cert_type="Root CA",
                           details=details, pem_files=pem_files,
                           back_url=url_for("rootca"),
                           export_url=url_for("export_cert", name=name))

@app.route("/rootca/export/<name>")
@admin_required
def export_cert(name):
    safe_name = secure_filename(name)
    ca_dir = os.path.join("data", "rootca", safe_name)
    cert_path = os.path.join(ca_dir, "cert.pem")
    key_path = os.path.join(ca_dir, "key.pem")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        flash("Certificate files not found", "error")
        return redirect(url_for("rootca"))

    _audit_log("Exported Root CA", target=name)
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
        flash("Name confirmation mismatch. Deletion cancelled.", "error")
        return redirect(url_for("rootca"))

    path = os.path.join("data", "rootca", secure_filename(name))
    if os.path.exists(path):
        import shutil
        shutil.rmtree(path)

    conn = get_db()
    conn.execute("DELETE FROM root_cas WHERE name = ?", (name,))
    conn.commit()
    conn.close()

    _audit_log("Deleted Root CA", target=name)
    flash(f"Deleted Root CA: {name}", "success")
    return redirect(url_for("rootca"))

# ---------- SSL CERTIFICATE ROUTES ----------

@app.route("/ssl", methods=["GET"])
@login_required
def ssl_page():
    conn = get_db()
    rows = conn.execute("SELECT * FROM root_cas").fetchall()
    conn.close()

    def _attr(name_obj, oid, default=""):
        attrs = name_obj.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else default

    rootcas = []
    for row in rows:
        ca_cert_path = os.path.join(row["path"], "cert.pem")
        org = country = ""
        if os.path.exists(ca_cert_path):
            with open(ca_cert_path, "rb") as f:
                ca_cert_obj = x509.load_pem_x509_certificate(f.read())
            org = _attr(ca_cert_obj.subject, NameOID.ORGANIZATION_NAME)
            country = _attr(ca_cert_obj.subject, NameOID.COUNTRY_NAME)
            state = _attr(ca_cert_obj.subject, NameOID.STATE_OR_PROVINCE_NAME)
            locality = _attr(ca_cert_obj.subject, NameOID.LOCALITY_NAME)
            ou = _attr(ca_cert_obj.subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
        rootcas.append({"name": row["name"], "org": org, "country": country,
                        "state": state, "locality": locality, "ou": ou})
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

                details = _cert_details(cert_obj)
                certs.append({
                    "name": name,
                    "created": cert_obj.not_valid_before_utc.strftime("%Y-%m-%d"),
                    "expires": cert_obj.not_valid_after_utc.strftime("%Y-%m-%d"),
                    "root_ca": root_ca_name or "Unknown",
                    "details": details,
                })

    return render_template("ssl.html", rootcas=rootcas, certs=certs)

@app.route("/ssl/view/<name>")
@login_required
def view_ssl(name):
    safe_name = secure_filename(name)
    ssl_dir = os.path.join("data", "ssl", safe_name)
    cert_path      = os.path.join(ssl_dir, "cert.pem")
    key_path       = os.path.join(ssl_dir, "key.pem")
    fullchain_path = os.path.join(ssl_dir, "fullchain.pem")
    meta_path      = os.path.join(ssl_dir, "meta.txt")
    if not os.path.exists(cert_path):
        flash("Certificate not found.", "error")
        return redirect(url_for("ssl_page"))
    with open(cert_path, "rb") as f:
        cert_obj = x509.load_pem_x509_certificate(f.read())
    root_ca = ""
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            root_ca = f.read().strip()
    details = _cert_details(cert_obj)
    details["root_ca"] = root_ca
    pem_files = {"Certificate": open(cert_path).read()}
    if os.path.exists(key_path):
        pem_files["Private Key"] = open(key_path).read()
    if os.path.exists(fullchain_path):
        pem_files["Full Chain"] = open(fullchain_path).read()
    _audit_log("Viewed SSL Certificate", target=name, details=", ".join(pem_files.keys()))
    return render_template("cert_detail.html", name=name, cert_type="SSL Certificate",
                           details=details, pem_files=pem_files,
                           back_url=url_for("ssl_page"),
                           export_url=url_for("export_ssl", name=name))

@app.route("/ssl/create", methods=["POST"])
@login_required
def create_ssl():
    name = request.form.get("name")
    common_name = request.form.get("common_name")
    days = _days_until(request.form.get("expiry_date"), fallback=365)
    selected_ca = request.form.get("root_ca")
    sans_raw = request.form.get("sans", "")

    if not all([name, common_name, selected_ca]):
        flash("All fields are required.", "error")
        return redirect(url_for("ssl_page"))

    ca_dir = os.path.join("data", "rootca", secure_filename(selected_ca))
    ssl_dir = os.path.join("data", "ssl", secure_filename(name))
    os.makedirs(ssl_dir, exist_ok=True)

    ca_cert_path = os.path.join(ca_dir, "cert.pem")
    ca_key_path = os.path.join(ca_dir, "key.pem")

    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        flash("Selected Root CA not found.", "error")
        return redirect(url_for("ssl_page"))

    # Load CA certificate and key
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Inherit org and country from the signing CA
    def _attr(name_obj, oid, default=""):
        attrs = name_obj.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else default

    country = _attr(ca_cert.subject, NameOID.COUNTRY_NAME, "US")
    state = _attr(ca_cert.subject, NameOID.STATE_OR_PROVINCE_NAME)
    locality = _attr(ca_cert.subject, NameOID.LOCALITY_NAME)
    org = _attr(ca_cert.subject, NameOID.ORGANIZATION_NAME, "Certo")
    ou = _attr(ca_cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME)

    # Generate private key
    ssl_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build subject name (inherit full identity from CA, only CN is specific to this cert)
    ssl_name_attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, country)]
    if state:
        ssl_name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        ssl_name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    ssl_name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou:
        ssl_name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    ssl_name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    subject = x509.Name(ssl_name_attrs)

    # Build SAN list — always include CN, plus any extra entries from the form
    san_entries = []
    seen = set()
    for entry in ([common_name] + [s.strip() for s in sans_raw.replace(",", "\n").splitlines() if s.strip()]):
        if entry in seen:
            continue
        seen.add(entry)
        try:
            san_entries.append(x509.IPAddress(_ipaddress.ip_address(entry)))
        except ValueError:
            san_entries.append(x509.DNSName(entry))

    # Build certificate
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(ca_cert.subject) \
        .public_key(ssl_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False) \
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        ), critical=True) \
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False) \
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ssl_key.public_key()), critical=False) \
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False) \
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

    _audit_log("Created SSL Certificate", target=name)
    flash(f"SSL certificate '{name}' created successfully.", "success")
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
        flash("SSL certificate files not found.", "error")
        return redirect(url_for("ssl_page"))

    _audit_log("Exported SSL Certificate", target=name)
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
    days = _days_until(request.form.get("expiry_date"), fallback=365)

    key_path = os.path.join(ssl_dir, "key.pem")
    cert_path = os.path.join(ssl_dir, "cert.pem")
    meta_path = os.path.join(ssl_dir, "meta.txt")

    if not all([os.path.exists(p) for p in [key_path, meta_path]]):
        flash("Missing key or meta information.", "error")
        return redirect(url_for("ssl_page"))

    with open(key_path, "rb") as f:
        ssl_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(meta_path, "r") as f:
        root_ca = f.read().strip()

    ca_dir = os.path.join("data", "rootca", secure_filename(root_ca))
    ca_cert_path = os.path.join(ca_dir, "cert.pem")
    ca_key_path = os.path.join(ca_dir, "key.pem")

    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        flash("Root CA used for signing not found.", "error")
        return redirect(url_for("ssl_page"))

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Read existing cert to preserve subject and SANs
    with open(cert_path, "rb") as f:
        existing_ssl_cert = x509.load_pem_x509_certificate(f.read())

    try:
        existing_san = existing_ssl_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        existing_san = x509.SubjectAlternativeName([x509.DNSName(
            existing_ssl_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        )])

    # Create new cert preserving subject and SANs
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(existing_ssl_cert.subject) \
        .issuer_name(ca_cert.subject) \
        .public_key(ssl_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .add_extension(existing_san, critical=False) \
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        ), critical=True) \
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False) \
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ssl_key.public_key()), critical=False) \
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False) \
        .sign(ca_key, hashes.SHA256())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Regenerate fullchain.pem with updated leaf cert
    fullchain_path = os.path.join(ssl_dir, "fullchain.pem")
    with open(fullchain_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    _audit_log("Reissued SSL Certificate", target=name)
    flash(f"Reissued SSL certificate '{name}' successfully.", "success")
    return redirect(url_for("ssl_page"))

@app.route("/ssl/delete", methods=["POST"])
@login_required
def delete_ssl():
    name = request.form.get("name")
    confirm_name = request.form.get("confirm_name")

    if name != confirm_name:
        flash("Confirmation name does not match.", "error")
        return redirect(url_for("ssl_page"))

    ssl_path = os.path.join("data", "ssl", secure_filename(name))
    if os.path.exists(ssl_path):
        import shutil
        shutil.rmtree(ssl_path)
        _audit_log("Deleted SSL Certificate", target=name)
        flash(f"Deleted SSL certificate: {name}", "success")
    else:
        flash("SSL certificate not found.", "error")

    return redirect(url_for("ssl_page"))

@app.route("/ssl/import", methods=["POST"])
@login_required
def import_ssl():
    name = request.form.get("name")
    root_ca = request.form.get("root_ca")
    cert = request.files.get("cert")
    key = request.files.get("key")

    if not all([name, root_ca, cert, key]):
        flash("All fields are required.", "error")
        return redirect(url_for("ssl_page"))

    save_dir = os.path.join("data", "ssl", secure_filename(name))
    os.makedirs(save_dir, exist_ok=True)

    cert.save(os.path.join(save_dir, "cert.pem"))
    key.save(os.path.join(save_dir, "key.pem"))

    with open(os.path.join(save_dir, "meta.txt"), "w") as f:
        f.write(root_ca)

    _audit_log("Imported SSL Certificate", target=name, details=f"Root CA: {root_ca}")
    flash(f"SSL certificate '{name}' imported.", "success")
    return redirect(url_for("ssl_page"))

@app.route("/admin/activity-trail")
@admin_required
def activity_trail():
    per_page = 50
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    offset = (page - 1) * per_page

    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    logs = conn.execute(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (per_page, offset)
    ).fetchall()
    conn.close()

    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template("activity_trail.html", logs=logs, page=page,
                           total_pages=total_pages, total=total)

@app.route("/admin/users")
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute("SELECT username, role, full_name, email, mfa_enabled, enabled FROM users ORDER BY role, username").fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_users_create():
    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "user")
    password = request.form.get("password", "")

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("admin_users"))
    if role not in ("admin", "user"):
        flash("Invalid role.", "error")
        return redirect(url_for("admin_users"))

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash, role, full_name, email) VALUES (?,?,?,?,?)",
                     (username, hashed, role, full_name, email))
        conn.commit()
    except Exception:
        conn.close()
        flash(f"Username '{username}' already exists.", "error")
        return redirect(url_for("admin_users"))
    conn.close()
    _audit_log("Created User", target=username, details=f"role={role}")
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/edit", methods=["POST"])
@admin_required
def admin_users_edit(username):
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "user")

    if role not in ("admin", "user"):
        flash("Invalid role.", "error")
        return redirect(url_for("admin_users"))

    conn = get_db()
    conn.execute("UPDATE users SET full_name=?, email=?, role=? WHERE username=?",
                 (full_name, email, role, username))
    conn.commit()
    conn.close()
    _audit_log("Edited User", target=username, details=f"role={role}")
    flash(f"User '{username}' updated.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/reset-password", methods=["POST"])
@admin_required
def admin_users_reset_password(username):
    new_password = request.form.get("new_password", "")
    if len(new_password) < 4:
        flash("Password must be at least 4 characters.", "error")
        return redirect(url_for("admin_users"))

    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (hashed, username))
    conn.commit()
    conn.close()
    _audit_log("Reset User Password", target=username)
    flash(f"Password reset for '{username}'.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def admin_users_delete(username):
    if username == session.get("username"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_users"))
    conn = get_db()
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.execute("DELETE FROM backup_codes WHERE username=?", (username,))
    conn.commit()
    conn.close()
    _audit_log("Deleted User", target=username)
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/toggle-status", methods=["POST"])
@admin_required
def admin_users_toggle_status(username):
    if username == session.get("username"):
        flash("You cannot disable your own account.", "error")
        return redirect(url_for("admin_users"))
    conn = get_db()
    user = conn.execute("SELECT enabled FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))
    new_status = 0 if user["enabled"] else 1
    conn.execute("UPDATE users SET enabled=? WHERE username=?", (new_status, username))
    conn.commit()
    conn.close()
    action = "Enabled User" if new_status else "Disabled User"
    _audit_log(action, target=username)
    flash(f"User '{username}' {'enabled' if new_status else 'disabled'}.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/reset-mfa", methods=["POST"])
@admin_required
def admin_users_reset_mfa(username):
    conn = get_db()
    conn.execute("UPDATE users SET mfa_secret=NULL, mfa_enabled=0 WHERE username=?", (username,))
    conn.execute("DELETE FROM backup_codes WHERE username=?", (username,))
    conn.commit()
    conn.close()
    _audit_log("Reset User MFA", target=username)
    flash(f"MFA reset for '{username}'. They can now log in without MFA.", "success")
    return redirect(url_for("admin_users"))

@app.route("/branding/logo")
def branding_logo():
    conn = get_db()
    row = conn.execute("SELECT logo_path FROM branding WHERE id = 1").fetchone()
    conn.close()
    if row and row["logo_path"] and os.path.exists(row["logo_path"]):
        return send_file(row["logo_path"])
    return "", 404

_ALLOWED_LOGO_EXTS = {"png", "jpg", "jpeg", "gif", "svg", "webp"}

@app.route("/admin/branding", methods=["GET", "POST"])
@admin_required
def admin_branding():
    conn = get_db()
    branding = conn.execute("SELECT * FROM branding WHERE id = 1").fetchone()
    conn.close()

    if request.method == "POST":
        org_name = request.form.get("org_name", "").strip()
        logo = request.files.get("logo")
        logo_path = branding["logo_path"] if branding else ""

        if logo and logo.filename:
            ext = logo.filename.rsplit(".", 1)[-1].lower()
            if ext not in _ALLOWED_LOGO_EXTS:
                flash("Unsupported file type. Use PNG, JPG, GIF, SVG, or WebP.", "error")
                return redirect(url_for("admin_branding"))
            os.makedirs("data/branding", exist_ok=True)
            # Remove old logo file if it exists
            if logo_path and os.path.exists(logo_path):
                os.remove(logo_path)
            logo_path = os.path.join("data", "branding", f"logo.{ext}")
            logo.save(logo_path)

        conn = get_db()
        conn.execute("UPDATE branding SET org_name = ?, logo_path = ? WHERE id = 1",
                     (org_name, logo_path))
        conn.commit()
        conn.close()
        _audit_log("Updated Branding", details=f"org_name={org_name}")
        flash("Branding settings saved.", "success")
        return redirect(url_for("admin_branding"))

    return render_template("admin_branding.html", branding=branding)

@app.route("/admin/branding/remove-logo", methods=["POST"])
@admin_required
def remove_branding_logo():
    conn = get_db()
    row = conn.execute("SELECT logo_path FROM branding WHERE id = 1").fetchone()
    if row and row["logo_path"] and os.path.exists(row["logo_path"]):
        os.remove(row["logo_path"])
    conn.execute("UPDATE branding SET logo_path = '' WHERE id = 1")
    conn.commit()
    conn.close()
    _audit_log("Removed Branding Logo")
    flash("Logo removed.", "success")
    return redirect(url_for("admin_branding"))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8080, ssl_context=(CERT_PATH, KEY_PATH))
