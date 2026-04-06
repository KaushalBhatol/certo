# Certo — SSL Certificate Management & Private CA

Certo is a self-hosted, web-based SSL Certificate Authority (CA) and certificate management tool. It is designed to run entirely on your own infrastructure — including fully air-gapped networks — with no external dependencies at runtime.

---

## Air-Gapped / Offline Network Support

Certo is built for environments with no internet access:

- All frontend assets (Bootstrap 5, icons, fonts) are bundled locally — no CDN calls
- The Docker image carries every Python dependency inside the image
- TLS is self-terminated by the app itself using a generated self-signed certificate — no external CA is needed to bootstrap
- Zero outbound network calls at startup or during normal operation

---

## Core Features

### Root CA Management
- **Create a Root CA** — generate an RSA 2048-bit self-signed CA with full X.509 attributes (Country, State, Locality, Organization, OU, Common Name) and a custom expiry date
- **Import an existing Root CA** — upload an existing cert + key pair to manage it through Certo
- **Reissue a Root CA** — regenerate the CA certificate with a new validity period while keeping the same key material
- **View CA details** — inspect Subject, Issuer, Serial, validity dates, and fingerprint in the UI
- **Export Root CA** — download the CA certificate as PEM for distribution to clients/devices
- **Delete Root CA** — remove a CA and its associated files

### SSL Certificate Management
- **Issue SSL certificates** signed by any managed Root CA
- **Subject Alternative Names (SAN)** — add multiple DNS names and IP addresses per certificate
- **Certificate types** — standard SSL/TLS (Server Auth + Client Auth EKUs)
- **Custom expiry** — set any validity period per certificate
- **Reissue** — renew an existing SSL cert (new key + cert, same name) signed by the same or a different CA
- **Import SSL certificates** — bring in externally issued cert + key pairs
- **Export as ZIP** — download a ZIP archive containing `cert.pem`, `key.pem`, `fullchain.pem`, and `meta.txt`
- **View certificate details** — Subject, SAN list, Issuer, validity, and fingerprint
- **Delete certificates**

### RDP Certificate Management (Beta)
- Issue certificates with the Microsoft RDP Extended Key Usage OID (`1.3.6.1.4.1.311.54.1.2`) for use with Windows Remote Desktop Services
- Supports combined SSL + RDP EKU certificates
- Full lifecycle: create, view, reissue, import, export (ZIP), delete

### Dashboard
- Live summary counts of Root CAs, SSL certs, and RDP certs
- **Expiry warnings** — certificates expiring within 30 days (or already expired) are highlighted
- Recent audit activity feed (last 5 events)

---

## Security Features

### Authentication
- Username + password login with **bcrypt** password hashing
- **TOTP-based MFA** (compatible with any authenticator app — Google Authenticator, Authy, etc.)
- MFA setup via QR code scan in the web UI
- **Backup codes** (bcrypt-hashed) for MFA recovery; codes can be regenerated
- Admin can reset a user's MFA remotely

### Session Management
- Configurable **auto-logout** timeout per user
- Absolute session hard cap of 3 hours regardless of activity
- Sessions are signed cookies protected by `SECRET_KEY`

### Role-Based Access Control
| Capability | Admin | User |
|---|---|---|
| Manage Root CAs | Yes | No |
| Issue / manage SSL certs | Yes | Yes |
| Issue / manage RDP certs | Yes | Yes |
| User administration | Yes | No |
| Branding configuration | Yes | No |
| Activity trail | Yes | No |

### Transport Security
- App serves HTTPS on port 8080 using a self-generated certificate
- Automatic HTTP → HTTPS redirect (disabled in debug/localhost mode)

---

## Administration

### User Management
- Create, edit, enable/disable, and delete users
- Reset user passwords
- Reset user MFA
- Assign roles (`admin` or `user`)

### Audit Trail
- Every admin and user action is logged with timestamp, actor username, action type, target, and source IP
- Logs are automatically purged after 90 days
- Filterable activity trail view in the admin panel

### Branding
- Upload a custom logo displayed in the navigation bar
- Set a custom application name and color theme
- Reset branding to defaults

---

## Deployment

### Docker (recommended)
```bash
./generate_env.sh        # Generates .env with a random SECRET_KEY
docker-compose up -d
```

Environment variables:
| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | — (required) | Flask session signing key |
| `GUNICORN_WORKERS` | `2` | Number of Gunicorn worker processes |

### Local / bare-metal
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

App is available at `https://0.0.0.0:8080`. Default credentials: `admin` / `certo`.

---

## Technical Stack

| Component | Technology |
|---|---|
| Backend | Python 3, Flask |
| Certificate operations | `cryptography` library (RSA 2048-bit, SHA-256) |
| Database | SQLite (file-based, no server required) |
| Frontend | Jinja2 templates, Bootstrap 5 (bundled) |
| Password hashing | bcrypt |
| MFA | pyotp (TOTP/RFC 6238) |
| Production server | Gunicorn (HTTPS) |

---

## Data Storage

All runtime data lives under `data/` (gitignored, persisted via Docker volume):

| Path | Contents |
|---|---|
| `data/db.sqlite` | Users, audit logs, CA metadata, branding |
| `data/rootca/<name>/` | Root CA `cert.pem` and `key.pem` |
| `data/ssl/<name>/` | SSL cert + key + fullchain PEM files |
| `data/rdp/<name>/` | RDP cert + key + fullchain PEM files |

---

## Use Cases

- Private internal PKI for homelab, enterprise, or isolated networks
- Issuing trusted certificates for internal services without paying a public CA
- Air-gapped environments (OT/ICS networks, secure government networks, isolated data centers)
- Windows RDP certificate management without Active Directory Certificate Services
- Development and staging environments requiring real certificate chains
