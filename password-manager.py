#!/usr/bin/env python3

import base64
import getpass
import hashlib
import json
import os
import secrets
import string
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VAULT_FILE = Path.home() / ".password-vault.enc"

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32


# ============================================================
# KEY DERIVATION
# ============================================================

def derive_key(master_password, salt):
    """
    Convert the master password into a 256-bit encryption key.
    PBKDF2 makes password guessing significantly more expensive.
    """

    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE
    )


# ============================================================
# PASSWORD GENERATOR
# ============================================================

def generate_password(length=20):
    """
    Generate a cryptographically secure random password.
    """

    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*()-_=+[]{}"
    )

    while True:
        password = "".join(
            secrets.choice(characters)
            for _ in range(length)
        )

        # Make sure the generated password has good variety.
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+[]{}" for c in password)
        ):
            return password


# ============================================================
# VAULT ENCRYPTION
# ============================================================

def encrypt_vault(vault, master_password):
    """
    Encrypt the complete vault using AES-256-GCM.
    """

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(master_password, salt)

    plaintext = json.dumps(
        vault,
        ensure_ascii=False,
        indent=2
    ).encode("utf-8")

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    encrypted_data = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii")
    }

    return encrypted_data


# ============================================================
# VAULT DECRYPTION
# ============================================================

def decrypt_vault(encrypted_data, master_password):
    """
    Decrypt the vault.
    AES-GCM also verifies that the encrypted data has not
    been modified.
    """

    try:
        salt = base64.b64decode(encrypted_data["salt"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])

        key = derive_key(master_password, salt)

        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        return json.loads(
            plaintext.decode("utf-8")
        )

    except Exception:
        raise ValueError(
            "Invalid master password or corrupted vault."
        )


# ============================================================
# FILE OPERATIONS
# ============================================================

def save_vault(vault, master_password):
    """
    Encrypt and save the vault to disk.
    """

    encrypted_data = encrypt_vault(
        vault,
        master_password
    )

    temporary_file = VAULT_FILE.with_suffix(".tmp")

    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(
            encrypted_data,
            file,
            indent=2
        )

    # Restrict temporary file permissions.
    os.chmod(temporary_file, 0o600)

    # Replace the old vault atomically.
    os.replace(
        temporary_file,
        VAULT_FILE
    )

    # Ensure final file permissions are private.
    os.chmod(VAULT_FILE, 0o600)


def load_vault(master_password):
    """
    Load and decrypt an existing vault.
    """

    if not VAULT_FILE.exists():
        return None

    try:
        with open(
            VAULT_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            encrypted_data = json.load(file)

        return decrypt_vault(
            encrypted_data,
            master_password
        )

    except json.JSONDecodeError:
        raise ValueError("Vault file is corrupted.")

    except ValueError:
        raise

    except Exception:
        raise ValueError(
            "Unable to read the vault."
        )


# ============================================================
# FIRST-TIME SETUP
# ============================================================

def create_vault():
    print("\n=== First-Time Setup ===")
    print("Create your master password.")
    print("This password protects the entire vault.")
    print()

    while True:
        password1 = getpass.getpass(
            "Create master password: "
        )

        if len(password1) < 12:
            print(
                "Master password must be at least "
                "12 characters."
            )
            continue

        password2 = getpass.getpass(
            "Confirm master password: "
        )

        if password1 != password2:
            print("Passwords do not match.")
            continue

        break

    vault = {
        "entries": []
    }

    save_vault(
        vault,
        password1
    )

    print("\nVault created successfully.")
    print(f"Encrypted vault: {VAULT_FILE}")

    return vault, password1


# ============================================================
# LOGIN
# ============================================================

def login():
    """
    Open existing vault using the master password.
    """

    print("========================================")
    print("         PYTHON PASSWORD MANAGER")
    print("========================================")
    print()

    if not VAULT_FILE.exists():
        return create_vault()

    print("Encrypted vault found.")
    print()

    for attempt in range(3):
        master_password = getpass.getpass(
            "Master password: "
        )

        try:
            vault = load_vault(
                master_password
            )

            print("\nLogin successful.")
            return vault, master_password

        except ValueError:
            print(
                f"Invalid password or vault error. "
                f"Attempt {attempt + 1}/3."
            )

    print("\nToo many failed attempts.")
    sys.exit(1)


# ============================================================
# ADD PASSWORD
# ============================================================

def add_password(vault, master_password):
    print("\n========== ADD PASSWORD ==========")

    website = input(
        "Website/service: "
    ).strip()

    if not website:
        print("Website cannot be empty.")
        return

    username = input(
        "Username/email: "
    ).strip()

    if not username:
        print("Username cannot be empty.")
        return

    print("\nPassword options:")
    print("1. Enter password manually")
    print("2. Generate secure password")

    choice = input(
        "Choose option: "
    ).strip()

    if choice == "2":
        password = generate_password()

        print(
            f"\nGenerated password:\n{password}"
        )

        save_generated = input(
            "Save this password? [Y/n]: "
        ).strip().lower()

        if save_generated == "n":
            print("Entry cancelled.")
            return

    else:
        password = getpass.getpass(
            "Password: "
        )

        if not password:
            print("Password cannot be empty.")
            return

    notes = input(
        "Notes (optional): "
    ).strip()

    entry = {
        "id": secrets.token_hex(8),
        "website": website,
        "username": username,
        "password": password,
        "notes": notes
    }

    vault["entries"].append(entry)

    save_vault(
        vault,
        master_password
    )

    print("\nPassword saved successfully.")


# ============================================================
# LIST PASSWORDS
# ============================================================

def list_passwords(vault):
    entries = vault.get("entries", [])

    if not entries:
        print("\nNo password entries found.")
        return

    print("\n========== PASSWORD ENTRIES ==========")

    for number, entry in enumerate(entries, start=1):
        print(
            f"{number}. "
            f"{entry['website']} "
            f"({entry['username']})"
        )

    print()


# ============================================================
# VIEW PASSWORD
# ============================================================

def view_password(vault):
    entries = vault.get("entries", [])

    if not entries:
        print("\nNo password entries found.")
        return

    list_passwords(vault)

    choice = input(
        "Enter entry number to view: "
    ).strip()

    if not choice.isdigit():
        print("Invalid entry number.")
        return

    index = int(choice) - 1

    if index < 0 or index >= len(entries):
        print("Entry does not exist.")
        return

    entry = entries[index]

    print("\n========== PASSWORD DETAILS ==========")
    print(f"Website : {entry['website']}")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")

    if entry.get("notes"):
        print(f"Notes   : {entry['notes']}")


# ============================================================
# SEARCH
# ============================================================

def search_passwords(vault):
    entries = vault.get("entries", [])

    if not entries:
        print("\nNo password entries found.")
        return

    query = input(
        "\nSearch website or username: "
    ).strip().lower()

    if not query:
        print("Search cannot be empty.")
        return

    matches = []

    for entry in entries:
        website = entry["website"].lower()
        username = entry["username"].lower()
        notes = entry.get("notes", "").lower()

        if (
            query in website
            or query in username
            or query in notes
        ):
            matches.append(entry)

    if not matches:
        print("\nNo matching entries.")
        return

    print(
        f"\nFound {len(matches)} matching entry/entries:"
    )

    print("----------------------------------------")

    for number, entry in enumerate(matches, start=1):
        print(
            f"{number}. "
            f"{entry['website']} "
            f"({entry['username']})"
        )


# ============================================================
# DELETE PASSWORD
# ============================================================

def delete_password(vault, master_password):
    entries = vault.get("entries", [])

    if not entries:
        print("\nNo password entries found.")
        return

    list_passwords(vault)

    choice = input(
        "Enter entry number to delete: "
    ).strip()

    if not choice.isdigit():
        print("Invalid entry number.")
        return

    index = int(choice) - 1

    if index < 0 or index >= len(entries):
        print("Entry does not exist.")
        return

    entry = entries[index]

    print(
        f"\nSelected: "
        f"{entry['website']} ({entry['username']})"
    )

    confirmation = input(
        "Delete this entry? Type YES: "
    )

    if confirmation != "YES":
        print("Deletion cancelled.")
        return

    entries.pop(index)

    save_vault(
        vault,
        master_password
    )

    print("Entry deleted.")


# ============================================================
# CHANGE MASTER PASSWORD
# ============================================================

def change_master_password(vault, current_password):
    print("\n========== CHANGE MASTER PASSWORD ==========")

    old_password = getpass.getpass(
        "Current master password: "
    )

    if old_password != current_password:
        print("Incorrect current master password.")
        return current_password

    while True:
        new_password = getpass.getpass(
            "New master password: "
        )

        if len(new_password) < 12:
            print(
                "Master password must be at least "
                "12 characters."
            )
            continue

        confirm = getpass.getpass(
            "Confirm new master password: "
        )

        if new_password != confirm:
            print("Passwords do not match.")
            continue

        break

    save_vault(
        vault,
        new_password
    )

    print("\nMaster password changed successfully.")

    return new_password


# ============================================================
# GENERATE PASSWORD
# ============================================================

def password_generator():
    print("\n========== PASSWORD GENERATOR ==========")

    length_input = input(
        "Password length [20]: "
    ).strip()

    if not length_input:
        length = 20
    elif length_input.isdigit():
        length = int(length_input)
    else:
        print("Invalid length.")
        return

    if length < 8:
        print("Minimum length is 8.")
        return

    if length > 256:
        print("Maximum length is 256.")
        return

    password = generate_password(length)

    print("\nGenerated password:")
    print(password)

    print(
        "\nYou can use option 1 to save it "
        "inside the encrypted vault."
    )


# ============================================================
# ABOUT VAULT
# ============================================================

def vault_information(vault):
    entries = vault.get("entries", [])

    print("\n========== VAULT INFORMATION ==========")
    print(f"Vault file : {VAULT_FILE}")
    print(f"Entries    : {len(entries)}")
    print("Encryption : AES-256-GCM")
    print("KDF        : PBKDF2-HMAC-SHA256")
    print(
        f"Iterations : {PBKDF2_ITERATIONS:,}"
    )
    print("Storage    : Encrypted JSON")


# ============================================================
# MAIN MENU
# ============================================================

def main_menu(vault, master_password):

    while True:
        print("\n")
        print("========================================")
        print("          PASSWORD MANAGER")
        print("========================================")
        print("1. Add password")
        print("2. View password")
        print("3. List passwords")
        print("4. Search passwords")
        print("5. Delete password")
        print("6. Generate password")
        print("7. Change master password")
        print("8. Vault information")
        print("9. Exit")
        print("========================================")

        choice = input(
            "Select option: "
        ).strip()

        if choice == "1":
            add_password(
                vault,
                master_password
            )

        elif choice == "2":
            view_password(vault)

        elif choice == "3":
            list_passwords(vault)

        elif choice == "4":
            search_passwords(vault)

        elif choice == "5":
            delete_password(
                vault,
                master_password
            )

        elif choice == "6":
            password_generator()

        elif choice == "7":
            master_password = change_master_password(
                vault,
                master_password
            )

        elif choice == "8":
            vault_information(vault)

        elif choice == "9":
            print("\nVault closed.")
            print("Goodbye.")
            break

        else:
            print(
                "Invalid option. Enter a number "
                "from 1 to 9."
            )

    return master_password


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

def main():
    try:
        vault, master_password = login()

        main_menu(
            vault,
            master_password
        )

    except KeyboardInterrupt:
        print("\n\nVault closed.")
        sys.exit(0)

    except Exception as error:
        print(
            f"\nUnexpected error: {error}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
