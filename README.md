# Certo

**Certo** is a self-hosted, open-source SSL Certificate Management and Certificate Authority (CA) tool built with Python and Flask.

> Designed for internal teams, developers, and DevOps who need a lightweight, private CA they control.

---

## Project Info

- **Name:** Certo
- **Description:** Self-Hosted SSL Certificate Management and Authority
- **Author:** [bhatol.com](https://bhatol.com)
- **License:** GNU Affero General Public License v3.0 (AGPL-3.0)

---

## Features

### Certificate Authority
- Create and manage Root CAs (RSA 2048-bit, SHA-256)
- Reissue Root CAs (renews validity, preserves keypair and subject identity)
- Export Root CA as ZIP (cert + key)
- Import existing Root CA cert and key
- Delete Root CAs with name confirmation

### SSL Certificates
- Issue SSL certificates signed by any managed Root CA
- SubjectAlternativeName (SAN) support — hostname and IP entries, CN always included
- Proper X.509 extensions: `KeyUsage`, `ExtendedKeyUsage` (serverAuth + clientAuth), `SubjectKeyIdentifier`, `AuthorityKeyIdentifier`
- Reissue SSL certs (renews validity, preserves keypair, subject, and SANs)
- Export as ZIP (cert + key + fullchain.pem)
- Import existing SSL cert and key
- Delete with name confirmation
- `fullchain.pem` generated and kept up to date on reissue

### Authentication & Security
- Session-based login with bcrypt password hashing
- Role-based access: `admin` (full access) and `user` (SSL management only)
- TOTP-based two-factor authentication (MFA) with QR code setup
- 8 single-use backup codes generated on MFA enable (bcrypt-hashed, stored in DB)
- MFA disable requires password confirmation
- Admin can reset any user's MFA
- Admin can enable / disable user accounts

### Admin
- User management — create, edit, reset password, enable/disable, delete
- Activity Trail — full audit log of all actions (90-day retention, paginated)
- Branding — custom logo and organization name across the UI

### Personal Settings
- Update display name and email
- Change password
- Enable / disable MFA

### Infrastructure
- SQLite storage for users, Root CA index, audit logs, and MFA backup codes
- Certificate files stored on disk (`data/rootca/`, `data/ssl/`)
- Fully air-gap compatible — no CDN dependencies, all assets bundled locally
- HTTPS-only (self-signed cert auto-generated on first run)
- Production-ready Docker setup with Gunicorn

---

## Default Credentials

On first startup, if no users exist in the database, a default admin account is created:

| Username | Password |
|----------|----------|
| `admin`  | `certo`  |

> **Change the password immediately after first login.**

---

## Production Deployment (Docker)

### 1. Generate your `.env` file

```bash
./generate_env.sh
```

This creates a `.env` with a cryptographically random `SECRET_KEY`. Never commit this file.

### 2. Build and start

```bash
docker-compose up -d
```

### 3. Access

```
https://<your-host>:8080
```

The app serves HTTPS with a self-signed certificate generated on first run. Your browser will show a security warning — this is expected. Import the Root CA you create into your trust store to resolve it.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Flask session signing key — must be a long random string |
| `GUNICORN_WORKERS` | No | Number of worker processes (default: `2`) |

### Data Persistence

All data is stored in the `certo_data` Docker named volume mounted at `/app/data`. Certificates, the SQLite database, and the app's own TLS cert all live here. Back up this volume to preserve your CA and certificate data.

```bash
# Backup
docker run --rm -v certo_data:/data -v $(pwd):/backup alpine \
  tar czf /backup/certo_data_backup.tar.gz -C /data .

# Restore
docker run --rm -v certo_data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/certo_data_backup.tar.gz -C /data
```

### Upgrading

```bash
docker-compose pull   # if using a registry
docker-compose build  # if building locally
docker-compose up -d
```

Data is in a named volume and is not affected by image rebuilds.

---

## Local Development

### Requirements

- Python 3.10+

### Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

App runs at `https://0.0.0.0:8080`. Accept the browser warning for the self-signed cert.

#### Windows (PowerShell)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\install.ps1
```

---

## File Structure

```
certo/
├── app.py                  # Flask app — all routes and logic
├── utils/
│   ├── db.py               # SQLite connection and schema init
│   └── precheck.py         # Startup checks, cert generation, DB seed
├── templates/              # Jinja2 HTML templates
├── static/                 # Bootstrap CSS/JS, favicon (bundled, no CDN)
├── data/                   # Runtime data (gitignored, Docker volume)
│   ├── app.db              # SQLite database
│   ├── rootca/             # Root CA cert and key files
│   └── ssl/                # SSL cert, key, fullchain, and meta files
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh    # Runs precheck then starts Gunicorn with SSL
├── generate_env.sh         # Generates .env with a secure SECRET_KEY
└── requirements.txt
```
