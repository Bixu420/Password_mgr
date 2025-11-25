import argparse
from getpass import getpass

from passmgr.core.db import init_db, SessionLocal
from passmgr.core.security import create_user, verify_user
from passmgr.core.crypto import encrypt, decrypt
from passmgr.core.repository import create_entry, list_entries, get_entry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=["init", "add", "list", "show"])
    parser.add_argument("--username", required=True, help="Account username")
    parser.add_argument("--id", type=int, help="Entry ID for show")
    args = parser.parse_args()

    db = SessionLocal()

    # -----------------------------------------
    # INIT (create user account)
    # -----------------------------------------
    if args.cmd == "init":
        init_db()
        pw = getpass("Master password: ")

        try:
            create_user(db, args.username, pw)
            print(f"User '{args.username}' created.")
        except ValueError as e:
            print("Error:", e)
        return

    # -----------------------------------------
    # LOGIN (used for all other commands)
    # -----------------------------------------
    pw = getpass("Master password: ")
    try:
        key, user_id = verify_user(db, args.username, pw)
    except Exception:
        print("Invalid username or password.")
        return

    # -----------------------------------------
    # ADD ENTRY
    # -----------------------------------------
    if args.cmd == "add":
        name = input("Entry name: ").strip()
        entry_username = input("Username (optional): ").strip()
        entry_password = getpass("Password to store: ")
        url = input("URL (optional): ").strip()
        notes = input("Notes (optional): ").strip()

        e = create_entry(
            db,
            user_id=user_id,
            name=name,
            username=entry_username if entry_username else None,
            password_encrypted=encrypt(key, entry_password),
            url=url if url else None,
            notes_encrypted=encrypt(key, notes) if notes else None,
        )

        print("Created entry with ID:", e.id)

    # -----------------------------------------
    # LIST ENTRIES
    # -----------------------------------------
    elif args.cmd == "list":
        entries = list_entries(db, user_id)
        if not entries:
            print("No entries.")
            return
        for e in entries:
            print(f"{e.id}: {e.name} ({e.username or '-'})")

    # -----------------------------------------
    # SHOW ENTRY
    # -----------------------------------------
    elif args.cmd == "show":
        if not args.id:
            print("Please specify --id <entry_id>")
            return

        e = get_entry(db, args.id, user_id)
        if not e:
            print("Not found.")
            return

        print("Name:", e.name)
        print("Username:", e.username or "")
        print("Password:", decrypt(key, e.password_encrypted))
        print("URL:", e.url or "")
        if e.notes_encrypted:
            print("Notes:", decrypt(key, e.notes_encrypted))


if __name__ == "__main__":
    main()
