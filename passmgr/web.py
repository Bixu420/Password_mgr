from datetime import datetime, timedelta
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from passmgr.core.db import SessionLocal, init_db
from passmgr.core.security import verify_user, create_user
from passmgr.core.repository import create_entry, list_entries, get_entry, delete_entry
from passmgr.core.crypto import encrypt, decrypt

app = FastAPI(title="Password Manager")

# -----------------------------
# Serve the frontend
# -----------------------------
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def root():
    # serves static/index.html
    return FileResponse(str(STATIC_DIR / "index.html"))


# -----------------------------
# Session handling (cookie-based)
# -----------------------------
sessions: dict[str, dict] = {}
SESSION_DURATION = timedelta(hours=1)


def get_session(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        raise HTTPException(401, "Not logged in")

    s = sessions[session_id]
    if s["expires"] < datetime.utcnow():
        del sessions[session_id]
        raise HTTPException(401, "Session expired")

    return s


# -----------------------------
# Schemas
# -----------------------------
class Register(BaseModel):
    username: str
    master_password: str


class Login(BaseModel):
    username: str
    master_password: str


class EntryIn(BaseModel):
    name: str
    username: str | None = None
    password: str
    url: str | None = None
    notes: str | None = None


class EntryOut(BaseModel):
    id: int
    name: str
    username: str | None
    url: str | None


class EntryDetail(EntryOut):
    password: str
    notes: str | None


# -----------------------------
# Auth endpoints
# -----------------------------
@app.post("/register")
def register(req: Register):
    db = SessionLocal()
    try:
        create_user(db, req.username, req.master_password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"message": "User created"}


@app.post("/login")
def login(req: Login, response: Response):
    db = SessionLocal()
    try:
        key, user_id = verify_user(db, req.username, req.master_password)
    except Exception:
        raise HTTPException(401, "Invalid username or password")

    session_id = uuid.uuid4().hex
    sessions[session_id] = {
        "key": key,
        "user_id": user_id,
        "expires": datetime.utcnow() + SESSION_DURATION,
    }

    # IMPORTANT: set secure=True when using HTTPS
    response.set_cookie(
        "session_id",
        value=session_id,
        httponly=True,
        secure=False,  # change to True in production with HTTPS
        samesite="strict",
        max_age=SESSION_DURATION.seconds,
    )

    return {"message": "Logged in", "username": req.username}


@app.post("/logout")
def logout(response: Response, s=Depends(get_session), request: Request = None):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        del sessions[session_id]
    response.delete_cookie("session_id")
    return {"message": "Logged out"}


# -----------------------------
# Entry endpoints
# -----------------------------
@app.post("/entries", response_model=EntryOut)
def create_entry_api(data: EntryIn, s=Depends(get_session)):
    db = SessionLocal()

    e = create_entry(
        db,
        user_id=s["user_id"],
        name=data.name,
        username=data.username,
        password_encrypted=encrypt(s["key"], data.password),
        url=data.url,
        notes_encrypted=encrypt(s["key"], data.notes) if data.notes else None,
    )
    return EntryOut(id=e.id, name=e.name, username=e.username, url=e.url)


@app.get("/entries", response_model=list[EntryOut])
def list_entries_api(s=Depends(get_session)):
    db = SessionLocal()
    rows = list_entries(db, s["user_id"])
    return [
        EntryOut(id=e.id, name=e.name, username=e.username, url=e.url)
        for e in rows
    ]


@app.get("/entries/{entry_id}", response_model=EntryDetail)
def get_entry_api(entry_id: int, s=Depends(get_session)):
    db = SessionLocal()
    e = get_entry(db, entry_id, s["user_id"])
    if not e:
        raise HTTPException(404, "Not found")

    return EntryDetail(
        id=e.id,
        name=e.name,
        username=e.username,
        url=e.url,
        password=decrypt(s["key"], e.password_encrypted),
        notes=decrypt(s["key"], e.notes_encrypted) if e.notes_encrypted else None,
    )


@app.delete("/entries/{entry_id}", status_code=204)
def delete_entry_api(entry_id: int, s=Depends(get_session)):
    db = SessionLocal()
    if not delete_entry(db, entry_id, s["user_id"]):
        raise HTTPException(404, "Not found")
    return Response(status_code=204)


# -----------------------------
# Startup
# -----------------------------
@app.on_event("startup")
def startup():
    init_db()
    from passmgr.core.db import run_migrations
    run_migrations()
from datetime import datetime, timedelta
import uuid
import secrets
import time

from fastapi import FastAPI, HTTPException, Depends, Request, Response, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from passmgr.core.db import SessionLocal, init_db, run_migrations
from passmgr.core.security import verify_user, create_user
from passmgr.core.repository import create_entry, list_entries, get_entry, delete_entry
from passmgr.core.crypto import encrypt, decrypt
from passmgr.core.logging import logger

app = FastAPI(title="Password Manager")

# -----------------------------
# Static frontend
# -----------------------------
app.mount("/static", StaticFiles(directory="passmgr/static"), name="static")


@app.get("/")
def root():
    return FileResponse("passmgr/static/index.html")


# -----------------------------
# Global security settings
# -----------------------------

# In-memory sessions and rate limiting
sessions: dict[str, dict] = {}
SESSION_DURATION = timedelta(hours=1)

# login_attempts[(username, ip)] = [timestamps]
login_attempts: dict[tuple[str, str], list[float]] = {}

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300  # 5 minutes


# Security headers
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)

    # Strong CSP (only this origin)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )

    # HSTS – only meaningful over real HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Other security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    return response


# -----------------------------
# Helpers
# -----------------------------
def get_client_ip(request: Request) -> str:
    # basic, you can extend with X-Forwarded-For if behind proxy you trust
    client = request.client
    return client.host if client else "unknown"


def get_session(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        raise HTTPException(401, "Not logged in")

    s = sessions[session_id]
    if s["expires"] < datetime.utcnow():
        logger.info("Session expired for user_id=%s", s["user_id"])
        del sessions[session_id]
        raise HTTPException(401, "Session expired")

    return s


def require_csrf(
    request: Request,
    session=Depends(get_session),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
):
    if not csrf_header or csrf_header != session.get("csrf_token"):
        logger.warning(
            "CSRF validation failed for user_id=%s ip=%s",
            session.get("user_id"),
            get_client_ip(request),
        )
        raise HTTPException(status_code=403, detail="CSRF token invalid")
    return session


def rate_limit_login(username: str, ip: str):
    key = (username, ip)
    now = time.time()
    attempts = login_attempts.get(key, [])

    # remove expired attempts
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    attempts.append(now)

    login_attempts[key] = attempts

    if len(attempts) > MAX_LOGIN_ATTEMPTS:
        logger.warning(
            "Rate limit exceeded for username=%s ip=%s attempts=%s",
            username,
            ip,
            len(attempts),
        )
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later.",
        )


# -----------------------------
# Schemas
# -----------------------------
class Register(BaseModel):
    username: str
    master_password: str


class Login(BaseModel):
    username: str
    master_password: str


class EntryIn(BaseModel):
    name: str
    username: str | None = None
    password: str
    url: str | None = None
    notes: str | None = None


class EntryOut(BaseModel):
    id: int
    name: str
    username: str | None
    url: str | None


class EntryDetail(EntryOut):
    password: str
    notes: str | None


# -----------------------------
# Auth endpoints
# -----------------------------
@app.post("/register")
def register(req: Register, request: Request):
    db = SessionLocal()
    ip = get_client_ip(request)

    try:
        create_user(db, req.username, req.master_password)
        logger.info("User registered username=%s ip=%s", req.username, ip)
    except ValueError as e:
        logger.warning("Registration failed username=%s ip=%s reason=%s", req.username, ip, e)
        raise HTTPException(400, str(e))

    return {"message": "User created"}


@app.post("/login")
def login(req: Login, response: Response, request: Request):
    ip = get_client_ip(request)

    # rate limit per username+ip combo
    rate_limit_login(req.username, ip)

    db = SessionLocal()
    try:
        key, user_id = verify_user(db, req.username, req.master_password)
    except Exception:
        logger.warning("Login failed username=%s ip=%s", req.username, ip)
        raise HTTPException(401, "Invalid username or password")

    # successful login -> reset attempts
    login_attempts[(req.username, ip)] = []

    # create session
    session_id = uuid.uuid4().hex
    csrf_token = secrets.token_hex(32)

    sessions[session_id] = {
        "key": key,
        "user_id": user_id,
        "username": req.username,
        "csrf_token": csrf_token,
        "expires": datetime.utcnow() + SESSION_DURATION,
    }

    # secure cookie – only over HTTPS
    response.set_cookie(
        "session_id",
        value=session_id,
        httponly=True,
        secure=True,          # IMPORTANT: requires HTTPS between client and proxy
        samesite="strict",
        max_age=SESSION_DURATION.seconds,
        path="/",
    )

    logger.info("Login successful username=%s ip=%s", req.username, ip)

    # Send CSRF token in JSON body (frontend stores it in JS)
    return {"message": "Logged in", "username": req.username, "csrf_token": csrf_token}


@app.post("/logout")
def logout(
    request: Request,
    response: Response,
    session=Depends(require_csrf),
):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        logger.info(
            "Logout username=%s user_id=%s ip=%s",
            session.get("username"),
            session.get("user_id"),
            get_client_ip(request),
        )
        del sessions[session_id]
    response.delete_cookie("session_id")
    return {"message": "Logged out"}


# -----------------------------
# Entry endpoints
# -----------------------------
@app.post("/entries", response_model=EntryOut)
def create_entry_api(
    data: EntryIn,
    request: Request,
    session=Depends(require_csrf),
):
    db = SessionLocal()

    e = create_entry(
        db,
        user_id=session["user_id"],
        name=data.name,
        username=data.username,
        password_encrypted=encrypt(session["key"], data.password),
        url=data.url,
        notes_encrypted=encrypt(session["key"], data.notes) if data.notes else None,
    )

    logger.info(
        "Entry created user_id=%s entry_id=%s name=%s ip=%s",
        session["user_id"],
        e.id,
        e.name,
        get_client_ip(request),
    )

    return EntryOut(id=e.id, name=e.name, username=e.username, url=e.url)


@app.get("/entries", response_model=list[EntryOut])
def list_entries_api(request: Request, session=Depends(get_session)):
    db = SessionLocal()
    rows = list_entries(db, session["user_id"])
    logger.info(
        "Entries listed user_id=%s count=%s ip=%s",
        session["user_id"],
        len(rows),
        get_client_ip(request),
    )
    return [
        EntryOut(id=e.id, name=e.name, username=e.username, url=e.url)
        for e in rows
    ]


@app.get("/entries/{entry_id}", response_model=EntryDetail)
def get_entry_api(entry_id: int, request: Request, session=Depends(get_session)):
    db = SessionLocal()
    e = get_entry(db, entry_id, session["user_id"])
    if not e:
        logger.warning(
            "Entry not found user_id=%s entry_id=%s ip=%s",
            session["user_id"],
            entry_id,
            get_client_ip(request),
        )
        raise HTTPException(404, "Not found")

    logger.info(
        "Entry viewed user_id=%s entry_id=%s ip=%s",
        session["user_id"],
        entry_id,
        get_client_ip(request),
    )

    return EntryDetail(
        id=e.id,
        name=e.name,
        username=e.username,
        url=e.url,
        password=decrypt(session["key"], e.password_encrypted),
        notes=decrypt(session["key"], e.notes_encrypted) if e.notes_encrypted else None
    )


@app.delete("/entries/{entry_id}", status_code=204)
def delete_entry_api(
    entry_id: int,
    request: Request,
    session=Depends(require_csrf),
):
    db = SessionLocal()

    ok = delete_entry(db, entry_id, session["user_id"])
    if not ok:
        logger.warning(
            "Entry delete failed (not found) user_id=%s entry_id=%s ip=%s",
            session["user_id"],
            entry_id,
            get_client_ip(request),
        )
        raise HTTPException(404, "Not found")

    logger.info(
        "Entry deleted user_id=%s entry_id=%s ip=%s",
        session["user_id"],
        entry_id,
        get_client_ip(request),
    )

    # FastAPI with status_code=204 expects an empty response
    return Response(status_code=204)


# -----------------------------
# Startup
# -----------------------------
@app.on_event("startup")
def startup():
    init_db()
    try:
        run_migrations()
    except Exception as e:
        # Avoid crashing app on migration errors, but log clearly
        logger.error("Migration failed: %s", e)
