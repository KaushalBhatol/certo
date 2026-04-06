# Certo

**Certo** is a self-hosted, open-source SSL Certificate Management and Certificate Authority (CA) tool built with Python and Flask.

> Designed for internal teams, developers, and DevOps who need a lightweight, private CA they control.

[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-bhatol%2Fcerto-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/bhatol/certo)
[![GitHub](https://img.shields.io/badge/GitHub-KaushalBhatol%2Fcerto-181717?logo=github&logoColor=white)](https://github.com/KaushalBhatol/certo)
[![Bhatol](https://img.shields.io/badge/Bhatol-bhatol.com-FF6B35?logo=firefox&logoColor=white)](https://bhatol.com/)

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
- HTTP server (put Nginx/Caddy/Traefik in front for HTTPS in production)
- Production-ready Docker setup with Gunicorn

---

### Prevent Public Indexing (robots / noindex)

- The application is configured to discourage public search engine indexing and automated crawling:
  - A dynamic `robots.txt` endpoint is served at `/robots.txt` which disallows all user agents and sets a short crawl delay.
  - All HTTP responses include the `X-Robots-Tag: noindex, nofollow` header (see `app.py`).
  - The base template includes a `<meta name="robots" content="noindex, nofollow">` tag (see `templates/layout.html`).
- These measures help prevent accidental public indexing of internal CAs and certificates, but do not replace access controls — keep the app behind a VPN or firewall for production use.
- To change or disable this behavior, edit the `robots.txt` handler or the `@app.after_request` hook in `app.py`, or modify `templates/layout.html` to remove the meta tag. You can also serve a custom static `robots.txt` from the `static/` directory if preferred.

---

## Default Credentials

On first startup, if no users exist in the database, a default admin account is created:

| Username | Password |
|----------|----------|
| `admin`  | `certo`  |

> **Change the password immediately after first login.**

---

## Production Deployment (Docker)

### Option A — Docker Compose (recommended)

No setup required. Just run:

```bash
docker-compose up -d
```

Then open **http://&lt;your-host&gt;:8080** in your browser.

A secure `SECRET_KEY` is automatically generated on first start and persisted in the data volume — sessions survive container restarts.

To use a custom key, create a `.env` file before starting:

```env
SECRET_KEY=your-long-random-string-here
```

### Option B — Docker Run

```bash
docker run -d \
  -p 8080:8080 \
  --name certo \
  -v certo_data:/app/data \
  bhatol/certo:latest
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | No | Auto-generated | Flask session signing key. Auto-created and persisted in the data volume if not set. |
| `GUNICORN_WORKERS` | No | `2` | Number of Gunicorn worker processes |

### Data Persistence

All data is stored in the `certo_data` Docker named volume at `/app/data` — the SQLite database, Root CA files, and SSL certificate files. Back up this volume to preserve your data.

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
docker-compose pull
docker-compose up -d
```

Data is in a named volume and is not affected by image updates.

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

App runs at `http://0.0.0.0:8080`.

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
├── docker-entrypoint.sh    # Runs precheck then starts Gunicorn
├── generate_env.sh         # Optional: generates .env with a custom SECRET_KEY
└── requirements.txt
```
