import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


with open("encrypted.txt", "r") as f:
    blob = f.read().strip()

# Base64 decode
data = base64.b64decode(blob)

# Extract encryption components
salt = data[:16]
nonce = data[16:28]
ciphertext_and_tag = data[28:]

# Derive AES-256 key
password = b"horatio"

key = hashlib.pbkdf2_hmac(
    "sha256",
    password,
    salt,
    200000,
    32
)

# Decrypt
plaintext = AESGCM(key).decrypt(
    nonce,
    ciphertext_and_tag,
    None
)

print(plaintext.decode())
