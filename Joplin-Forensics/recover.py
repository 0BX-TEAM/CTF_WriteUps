from pathlib import Path
import re

wal = Path("database.sqlite-wal").read_bytes()

title = b"Delacroix \xe2\x80\x94 06/28 confirmation"

pos = wal.find(title)

if pos == -1:
    print("[-] Deleted note not found")
    exit()

print("[+] Deleted note found at offset:", pos)

data = wal[pos + len(title):pos + len(title) + 5000]

match = re.search(rb'[A-Za-z0-9+/=]{100,}', data)

if not match:
    print("[-] Encrypted blob not found")
    exit()

blob = match.group().decode()

print("[+] Encrypted blob found")
print("[+] Length:", len(blob))

with open("encrypted.txt", "w") as f:
    f.write(blob)

print("[+] Saved to encrypted.txt")
