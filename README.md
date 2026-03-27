# Certo

**Certo** is a self-hosted, open-source SSL Certification Management and Certificate Authority (CA) tool built with Python and Flask.

> ⚙️ Designed for internal teams, developers, and DevOps who need a lightweight, private CA they control.

---

## 🌐 Project Info

- **Name:** Certo
- **Description:** Self-Hosted SSL Certification Management and Authority
- **Author:** [bhatol.com](https://bhatol.com)
- **License:** GNU Affero General Public License v3.0 (AGPL-3.0)

---

## 🚀 Features

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

### Personal Settings
- Update display name and email
- Change password
- Enable / disable MFA

### Infrastructure
- SQLite storage for users, Root CA index, and MFA backup codes
- Certificate files stored on disk (`data/rootca/`, `data/ssl/`)
- Fully air-gap compatible — no CDN dependencies, all assets bundled locally
- HTTPS-only (self-signed cert auto-generated on first run)
- Docker support via `docker-compose.yml`

---

## 📦 Requirements

- Python 3.10+
- See `requirements.txt` for full dependency list (Flask, cryptography, bcrypt, pyotp, qrcode, pycountry, etc.)

### 📥 Install Dependencies

```bash
pip install -r requirements.txt

```

#### Windows

```ps
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\install.ps1
```

---

## 🔐 Default Credentials

On first startup, if no users exist in the database, a default admin account is created automatically:

| Username | Password |
|----------|----------|
| `admin`  | `certo`  |

> Change the password after first login.
