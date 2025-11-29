# Web Password Manager – Test Plan & Test Cases

## 1. Functional Tests

### F-REG-01: Register New User
1. POST /register with username + master_password  
**Expected:** 200 OK, user created

### F-LOGIN-01: Login Success
**Expected:**  
- JSON: { username, csrf_token }  
- Secure session cookie created  

### F-LOGIN-02: Login Failure
Use wrong password  
**Expected:** 401 Invalid username or password

### F-ENTRY-ADD-01: Add Entry
**Expected:** Entry created with encrypted fields

### F-ENTRY-LIST-01: List Entries
**Expected:**  
- Fields: id, name, username, url  
- Password NOT included  

### F-ENTRY-VIEW-01: View Entry
**Expected:** password decrypted correctly

### F-ENTRY-DEL-01: Delete Entry
**Expected:** 204 No Content

---

## 2. Security Tests

### SEC-CSRF-01: Missing CSRF
Send POST /entries without `X-CSRF-Token`  
**Expected:** 403 CSRF token invalid

### SEC-CSRF-02: Wrong Token
Send invalid token  
**Expected:** 403

### SEC-COOKIE-01: Cookie Flags
Inspect Set-Cookie  
**Expected:**  
- HttpOnly  
- Secure  
- SameSite=Strict  

### SEC-CSP-01: XSS Blocked
Try inline `<script>alert(1)</script>`  
**Expected:** Browser blocks execution

### SEC-SQL-01: SQL Injection Check
Try `' OR 1=1` in fields  
**Expected:** ORM blocks it, no extra rows

### SEC-RATE-01: Brute Force Test
More than 5 failed logins in 5 mins  
**Expected:** 429 Too many attempts

### SEC-SESSION-01: Session Expiration
Manipulate session timestamp  
**Expected:** 401 Session expired

---

## 3. API Behavior Tests

### API-STATUS-01
Send GET /entries without session  
**Expected:** 401

### API-STATUS-02
Send DELETE /entries/{id} for nonexistent entry  
**Expected:** 404

---

## 4. UI Tests

### UI-LIST-01
Load dashboard  
**Expected:** Table displays entries

### UI-VIEW-01
Click “View”  
**Expected:** Password appears in detail panel

### UI-DEL-01
Click “Delete”  
**Expected:** Row disappears, refresh table

---

## 5. Logging Tests

### LOG-01
Trigger failed login  
**Expected:** warning log entry

### LOG-02
Create/delete entry  
**Expected:** info log entries

### LOG-03
Ensure logs contain:  
- No passwords  
- No keys  
- No plaintext notes  

---

## 6. Database Tests

### DB-ENC-01
Inspect password_encrypted  
**Expected:** ciphertext, not plaintext

### DB-USER-01
Ensure entries tied to correct user_id  
**Expected:** Isolation enforced
