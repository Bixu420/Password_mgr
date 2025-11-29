import argparse
from getpass import getpass

from passmgr.core.db import init_db, SessionLocal
from passmgr.core.security import verify_master_password, init_master_password
from passmgr.core.crypto import encrypt, decrypt
from passmgr.core.repository import create_entry, list_entries, get_entry, delete_entry


def main():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    parser.add_argument("cmd", choices=["init", "add", "list", "show", "delete"])
    parser.add_argument("--id", type=int, help="Entry ID for show/delete")

    args = parser.parse_args()
    db = SessionLocal()

    # -------------------------
    # INIT COMMAND
    # -------------------------
    if args.cmd == "init":
        init_db()
        pw = getpass("Create master password: ")
        init_master_password(db, pw)
        print("Vault initialized.")
        return

    # -------------------------
    # ALL OTHER COMMANDS REQUIRE MASTER PASS
    # -------------------------
    master = getpass("Master password: ")
    key, user_id = verify_master_password(db, master)

    # -------------------------
    # ADD NEW ENTRY
    # -------------------------
    if args.cmd == "add":
        name = input("Name (e.g. Github): ").strip()
        username = input("Username: ").strip()
        password = getpass("Password: ")
        url = input("URL (optional): ").strip()
        notes = input("Notes (optional): ").strip()

        e = create_entry(
            db,
            user_id=user_id,
            name=name,
            username=username,
            password_encrypted=encrypt(key, password),
            url=url,
            notes_encrypted=encrypt(key, notes) if notes else None,
        )
        print(f"Entry created with ID: {e.id}")
        return

    # -------------------------
    # LIST ENTRIES (safe)
    # -------------------------
    if args.cmd == "list":
        print("\nStored entries:\n")
        print(f"{'ID':<5}{'Name':<20}{'Username':<20}{'URL'}")
        print("-" * 60)
        for e in list_entries(db, user_id):
            print(f"{e.id:<5}{e.name:<20}{e.username or '':<20}{e.url or ''}")
        print()
        return

    # -------------------------
    # SHOW PASSWORD OF ENTRY
    # -------------------------
    if args.cmd == "show":
        if not args.id:
            print("Error: --id required")
            return

        e = get_entry(db, args.id, user_id)
        if not e:
            print("Entry not found.")
            return

        print("\nEntry details:")
        print(f"Name: {e.name}")
        print(f"Username: {e.username}")
        print(f"Password: {decrypt(key, e.password_encrypted)}")
        print(f"URL: {e.url}")
        if e.notes_encrypted:
            print(f"Notes: {decrypt(key, e.notes_encrypted)}")
        print()
        return

    # -------------------------
    # DELETE ENTRY
    # -------------------------
    if args.cmd == "delete":
        if not args.id:
            print("Error: --id required")
            return

        ok = delete_entry(db, args.id, user_id)
        if not ok:
            print("Entry not found or does not belong to you.")
            return

        print(f"Entry {args.id} deleted.")
        return


if __name__ == "__main__":
    main()
