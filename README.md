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
uvicorn passmgr.web:app --host 0.0.0.0 --port 8001 \
  --ssl-keyfile=key.pem --ssl-certfile=cert.pem
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
- Session includes secure cookie + CSRF token  

### 4.2 Encryption
- AES‑GCM via Fernet  
- Passwords & notes encrypted at rest  
- Encryption key derived per session  

### 4.3 Secure Cookies
`HttpOnly=True`, `Secure=True`, `SameSite=Strict`

### 4.4 CSRF Protection
- 32‑byte token generated at login  
- Sent as JSON: `{csrf_token: ...}`  
- Required in header: `X-CSRF-Token`

### 4.5 XSS Protection
Strict CSP:
```
default-src 'self';
script-src 'self';
style-src 'self';
object-src 'none';
frame-ancestors 'none';
form-action 'self';
```

### 4.6 SQL Injection Prevention
- SQLAlchemy ORM  
- No raw SQL  
- All user inputs sanitized  

### 4.7 Rate Limiting
- 5 login attempts per 5 minutes  
- Per username + IP  

---

## 5. API Endpoints

### Auth Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Create a new user |
| POST | `/login` | Authenticate user |
| POST | `/logout` | Logout & invalidate session |

### Entry Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/entries` | Create encrypted entry |
| GET | `/entries` | List entries (no passwords) |
| GET | `/entries/{id}` | Decrypt & view entry |
| DELETE | `/entries/{id}` | Delete entry |

---

## 6. UI Overview

Features:
- Responsive premium‑styled UI  
- Password generator  
- Entry search  
- View / Delete entry actions  
- Secure logout  
- Session info panel  

All actions requiring modifications use CSRF‑protected requests.

---

# 📘 Project Report

## 1. Encryption Methods
The system uses **AES‑GCM encryption (via Fernet)** for all sensitive fields:  
- `password_encrypted`  
- `notes_encrypted`

Key derivation uses:
- PBKDF2‑HMAC‑SHA256  
- 200k iterations  
- Unique salt per user  

The encryption key is **never stored on disk**—only derived during session login.

---

## 2. Authentication Mechanisms
- Username + master password required  
- Master passwords hashed using bcrypt/PBKDF2  
- Login issues a session containing:
  - `session_id` via HttpOnly, Secure cookie  
  - `csrf_token` returned via JSON  

Session expires automatically after 1 hour.

---

## 3. Security Measures Implemented
✔ AES‑GCM encryption  
✔ CSRF protection  
✔ Secure cookies  
✔ Strict CSP for XSS protection  
✔ SQLAlchemy ORM (SQL injection prevention)  
✔ Input sanitization  
✔ Audit logging for:
- failed logins  
- brute force attempts  
- entry creation/deletion  
- CSRF failures  
✔ Session invalidation on logout  
✔ Rate limiting (5 attempts / 5 min)  

---

## 4. Mitigation of SQL Injection & XSS

### SQL Injection
- ORM parameterized queries ensure no unsafe SQL is constructed  
- No raw SQL using f-strings or concatenation  
- User inputs validated before database operations  

### XSS
- Strict CSP eliminates inline scripts  
- Static JS only from same origin  
- No dynamic HTML insertion—only `textContent` used  
- Browser blocks any inline script attempts  

---

## 5. Testing Results Summary

### ✔ Functional Tests Passed
- User registration  
- Login/logout  
- Encrypted entry creation  
- Listing entries without passwords  
- Viewing decrypted password securely  
- Deleting entries  
- UI operations functioning correctly  

### ✔ Security Tests Passed
- CSRF attacks blocked  
- XSS injection attempts blocked by CSP  
- SQL injection attempts blocked by ORM  
- Session expiration tested  
- Rate limiting triggered correctly  
- Cookies confirmed HttpOnly & Secure  
- DB inspected: encrypted fields unreadable  

The system successfully prevents:
- unauthorized access  
- XSS  
- SQL injection  
- CSRF  
- session hijacking  
- brute-force login attempts  

---

## 6. Test Cases Reference
Full functional and security test cases available in:

👉 **WEB_TESTS.md**

