import base64
import getpass
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



# Users for login + RBAC
# Passwords are stored as SHA-256 hashes.
USERS = {
    "alice": {
        "password_hash": hashlib.sha256("Password123!".encode()).hexdigest(),
        "role": "admin",
    },
    "bob": {
        "password_hash": hashlib.sha256("Student456!".encode()).hexdigest(),
        "role": "user",
    },
}

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
PACKAGE_FILE = DATA_DIR / "secure_package.json"
INPUT_FILE = DATA_DIR / "input_message.txt"
OUTPUT_FILE = DATA_DIR / "decrypted_message.txt"


# Authentication/authorization
def verify_password(username: str, password: str) -> bool:
    user = USERS.get(username)
    if not user:
        return False
    return hashlib.sha256(password.encode()).hexdigest() == user["password_hash"]


def login() -> Optional[dict]:
    print("\n=== Secure RBAC Demo ===")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if verify_password(username, password):
        role = USERS[username]["role"]
        print(f"Login successful. Welcome, {username}! Role: {role}")
        return {"username": username, "role": role}

    print("Login failed. Invalid username or password.")
    return None


def require_role(current_user: dict, allowed_roles: list[str]) -> bool:
    if current_user["role"] not in allowed_roles:
        print("Access denied: your role does not allow this action.")
        return False
    return True



# Cryptography helpers
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_aes_key() -> bytes:
    # 32 random bytes = 256-bit AES key
    return os.urandom(32)


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    # CBC mode needs a fresh random IV each time.
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext



# Digital signature helpers
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def sign_data(data: bytes, private_key) -> bytes:
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# Simple substitution cipher
def substitution_encrypt(message: str, shift: int = 3) -> str:
    result = []
    for ch in message:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def substitution_decrypt(message: str, shift: int = 3) -> str:
    return substitution_encrypt(message, -shift)


# File packaging helpers
def save_secure_package(username: str, role: str, original_hash: str, iv: bytes,
                        ciphertext: bytes, signature: bytes, public_key) -> None:
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    package = {
        "created_by": username,
        "role": role,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "sha256": original_hash,
        "iv_b64": base64.b64encode(iv).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "public_key_pem": public_pem,
    }

    PACKAGE_FILE.write_text(json.dumps(package, indent=2), encoding="utf-8")


# Main features
def encrypt_workflow(current_user: dict):
    if not require_role(current_user, ["admin", "user"]):
        return

    print("\nEnter a message to protect.")
    message = input("Message: ")
    plaintext = message.encode("utf-8")
    INPUT_FILE.write_bytes(plaintext)

    message_hash = sha256_hex(plaintext)
    aes_key = generate_aes_key()
    iv, ciphertext = aes_encrypt(plaintext, aes_key)

    private_key, public_key = generate_rsa_key_pair()
    signature = sign_data(ciphertext, private_key)

    save_secure_package(
        current_user["username"], current_user["role"], message_hash,
        iv, ciphertext, signature, public_key
    )

    print("\n--- Encryption Results ---")
    print(f"Original SHA-256 hash: {message_hash}")
    print(f"AES key (Base64, demo only): {base64.b64encode(aes_key).decode()}")
    print(f"IV (Base64): {base64.b64encode(iv).decode()}")
    print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}")
    print(f"Digital signature created: {base64.b64encode(signature).decode()[:60]}...")
    print(f"Saved package to: {PACKAGE_FILE}")
    print(f"Saved original input to: {INPUT_FILE}")
    print("IMPORTANT: Copy the AES key now. You will need it for decryption.")


def decrypt_and_verify_workflow(current_user: dict):
    if not require_role(current_user, ["admin"]):
        return

    if not PACKAGE_FILE.exists():
        print("No encrypted package found. Run the encryption step first.")
        return

    package = json.loads(PACKAGE_FILE.read_text(encoding="utf-8"))
    aes_key_b64 = input("Paste the AES key from the encryption step (Base64): ").strip()

    try:
        aes_key = base64.b64decode(aes_key_b64)
        iv = base64.b64decode(package["iv_b64"])
        ciphertext = base64.b64decode(package["ciphertext_b64"])
        signature = base64.b64decode(package["signature_b64"])

        public_key = serialization.load_pem_public_key(
            package["public_key_pem"].encode("utf-8")
        )
    except Exception as exc:
        print(f"Could not read the saved package or key: {exc}")
        return

    signature_ok = verify_signature(ciphertext, signature, public_key)
    if not signature_ok:
        print("Digital signature verification failed. The ciphertext may be untrusted.")
        return

    try:
        plaintext = aes_decrypt(iv, ciphertext, aes_key)
    except Exception as exc:
        print(f"Decryption failed: {exc}")
        return

    OUTPUT_FILE.write_bytes(plaintext)
    new_hash = sha256_hex(plaintext)
    original_hash = package["sha256"]
    integrity_ok = new_hash == original_hash

    print("\n--- Decryption Results ---")
    print(f"Decrypted message: {plaintext.decode('utf-8')}")
    print(f"Stored SHA-256 hash:   {original_hash}")
    print(f"Recomputed SHA-256:    {new_hash}")
    print(f"Digital signature OK?: {'Yes' if signature_ok else 'No'}")
    print(f"Integrity verified?:   {'Yes' if integrity_ok else 'No'}")
    print(f"Saved decrypted output to: {OUTPUT_FILE}")


def substitution_demo(current_user: dict):
    if not require_role(current_user, ["admin", "user"]):
        return

    message = input("\nEnter a message for the substitution cipher demo: ")
    encrypted = substitution_encrypt(message)
    decrypted = substitution_decrypt(encrypted)

    print("\n--- Simple Substitution Cipher Demo ---")
    print(f"Plaintext:  {message}")
    print(f"Encrypted:  {encrypted}")
    print(f"Decrypted:  {decrypted}")


def show_menu(current_user: dict):
    while True:
        print("\n=== Menu ===")
        print("1. Enter message -> SHA-256 -> AES encrypt -> digitally sign")
        print("2. Decrypt content -> verify digital signature -> compare hashes")
        print("3. Simple substitution cipher demo")
        print("4. Show role-based access info")
        print("5. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            encrypt_workflow(current_user)
        elif choice == "2":
            decrypt_and_verify_workflow(current_user)
        elif choice == "3":
            substitution_demo(current_user)
        elif choice == "4":
            print(f"\nYou are logged in as {current_user['username']} ({current_user['role']}).")
            print("Users can encrypt and run the substitution demo.")
            print("Only admins can decrypt and verify the protected package.")
        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    current_user = login()
    if current_user:
        show_menu(current_user)
