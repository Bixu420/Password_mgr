import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = os.getenv("PASSMGR_DB_PATH", str(DATA_DIR / "vault.db"))
LOG_PATH = os.getenv("PASSMGR_LOG_PATH", str(DATA_DIR / "passmgr.log"))
SESSION_SECRET_KEY = os.getenv("PASSMGR_SESSION_SECRET", "CHANGE_ME")
