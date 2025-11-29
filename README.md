# Web Password Manager – User & Developer Manual

## 1. Overview
This is a secure, browser‑based password manager built with FastAPI, SQLite, AES encryption, strict CSP, CSRF protection, and secure cookies.

## 2. Architecture
- **Frontend**: Static HTML/JS/CSS served via `/static`
- **Backend**: FastAPI application (`web.py`)
- **Database**: SQLite (`data/vault.db`)
- **Security Modules**: encryption, authentication, session mgmt, CSRF, rate limiting
- **Logging**: `data/passmgr.log`

### Data Flow
1. User logs in → server derives AES key from master password
2. Session cookie (`session_id`) issued, HttpOnly + Secure + SameSite
3. CSRF token returned via JSON for all mutating requests
4. All credentials encrypted at rest with AES (Fernet)

---

## 3. Installation & Running

### Install Dependencies
```
pip install -r requirements.txt
```

### Run with HTTPS
```
uvicorn passmgr.web:app --host 0.0.0.0 --port 8001   --ssl-keyfile=key.pem --ssl-certfile=cert.pem
```

Access in browser:
```
https://<server-ip>:8001/
```

---

## 4. Security Features

### 4.1 Authentication
- Master password hashed (bcrypt/PBKDF2)
- Never stored in plaintext
- Server derives encryption key only in session

### 4.2 Encryption
- AES-GCM via `cryptography.Fernet`
- `password_encrypted`, `notes_encrypted` stored encrypted

### 4.3 Secure Cookies
```
HttpOnly = True
Secure = True
SameSite = Strict
```

### 4.4 CSRF Protection
- Random 32-byte token created at login
- Sent in JSON `"csrf_token"`
- Required in header: `X-CSRF-Token`
- All modifying endpoints require CSRF

### 4.5 XSS Protection
Strict CSP:
```
default-src 'self';
script-src 'self';
style-src 'self';
frame-ancestors 'none';
object-src 'none';
```

### 4.6 SQL Injection Prevention
- SQLAlchemy ORM used everywhere
- No raw SQL from user input

### 4.7 Rate Limiting
- 5 login attempts per 5 mins per user+IP

---

## 5. API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Create new user |
| POST | `/login` | Authenticates and returns CSRF token |
| POST | `/logout` | Logs out, invalidates session |

### Entries
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/entries` | Create encrypted entry |
| GET | `/entries` | List entries (no passwords) |
| GET | `/entries/{id}` | View full entry (decrypt) |
| DELETE | `/entries/{id}` | Delete entry |

---

## 6. Frontend UI Overview

### Features
- Responsive premium‑styled UI
- Password generator
- Search filtering
- Table listing (ID, name, username, URL)
- “View” button decrypts entry
- “Delete” button (CSRF-protected)
- Session info panel

### Security UI Behavior
- No inline JS (CSP‑compliant)
- No passwords appear unless explicitly requested
- No secrets cached in DOM unnecessarily

---

## 7. Logs

Stored in:
```
passmgr/data/passmgr.log
```

Logs include:
- Login attempts
- Rate-limit violations
- Entry creation/deletion
- CSRF errors
- Session expiration

No sensitive data logged.

---

## 8. Deployment Notes

### Recommended
- Run behind Nginx reverse proxy
- Use real TLS certificate
- Store DB on encrypted filesystem
- Rotate log files
- Restrict system access

---

## 9. Troubleshooting

### Wrong CSRF Token
- Log out → refresh page → log in again

### Session Expired
- Log in again

### UI Not Loading
- Ensure static files served from `/static`
- Check browser console for CSP violations

### SSL Errors
- Use valid certificate or `--ssl-*` flags

---

## 10. Security Notes

- Master password is NEVER transmitted after login
- Server does not store encryption key
- All credential data encrypted at rest
- All communications over HTTPS only
