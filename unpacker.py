#!/usr/bin/env python3
import os
import sys
import re
import base64
import zlib
import hashlib
import ast
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Default constants from the original loader (fallback keys)
_DEFAULT_KEY = b'.\xff%\xa9\xa7\xa0,\x11h\x1e\x87Fy\xa5\x98\xe5-:AwxkXc\x84\xc1\xd9\xfb\xd1}\xeb\x80'
_DEFAULT_IV = b'!\xeb\x9a\xa5\xdf\xfa\x87\xfa\xf9\xbemC>\rN\xcb'


def detect_binary_type(data: bytes) -> str:
    if data.startswith(b'MZ'):
        return 'PE (Windows executable)'
    if data.startswith(b'\x7fELF'):
        return 'ELF (Unix executable)'
    if data[:2] in (b'#!',):
        return 'Script / Shebang'
    return 'Unknown / Other'


def extract_keys_from_loader(text: str) -> tuple[bytes, bytes] | None:
    """
    Extract _KEY and _IV from a loader script using AST parsing.
    Returns (key, iv) tuple if both found, None otherwise.
    """
    try:
        tree = ast.parse(text)
        found_key = None
        found_iv = None

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id == '_KEY' and isinstance(node.value, ast.Constant):
                            found_key = node.value.value
                        elif target.id == '_IV' and isinstance(node.value, ast.Constant):
                            found_iv = node.value.value

        if found_key and found_iv and isinstance(found_key, bytes) and isinstance(found_iv, bytes):
            return (found_key, found_iv)
    except SyntaxError:
        # If AST parsing fails, try regex fallback
        pass

    return None


def extract_encrypted_from_loader(text: str) -> str | None:
    """
    Try to pull the _encrypted string from a loader script. Handles a single
    (possibly multi-line) quoted string assigned to _encrypted inside parentheses.
    """
    pattern = re.compile(
        r"_encrypted\s*=\s*\(\s*(['\"])(?P<enc>.*?)\1\s*\)",
        re.DOTALL
    )
    m = pattern.search(text)
    if m:
        return m.group("enc")
    # fallback: maybe it's assigned without parentheses
    pattern2 = re.compile(
        r"_encrypted\s*=\s*(['\"])(?P<enc>.*?)\1", re.DOTALL)
    m2 = pattern2.search(text)
    if m2:
        return m2.group("enc")
    return None


def unpack(encrypted_str: str, key: bytes | None = None, iv: bytes | None = None) -> bytes:
    """
    Unpack encrypted data using provided keys or default keys.
    """
    if key is None:
        key = _DEFAULT_KEY
    if iv is None:
        iv = _DEFAULT_IV

    raw = base64.b85decode(encrypted_str)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(raw), 16)
    return zlib.decompress(decrypted)


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_blob(text: str) -> str:
    # strip surrounding quotes/newlines and whitespace
    return text.strip().strip('\'"').replace('\n', '')


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: unpacker.py <input-file-containing-blob-or-loader.py> <output-file> [--print-type] [--skip-write]")
        print(
            "Enhanced version with automatic key extraction - works with any packed file!")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    print(f"[*] Reading input from {in_path}")

    if not in_path.exists():
        print(f"[-] Input file {in_path} does not exist.")
        sys.exit(1)

    raw = in_path.read_text(errors="ignore")

    # Try to extract custom keys from the loader
    custom_keys = extract_keys_from_loader(raw)
    if custom_keys:
        key, iv = custom_keys
        print(
            f"[*] Extracted custom keys from loader: KEY={len(key)} bytes, IV={len(iv)} bytes")
    else:
        key, iv = None, None
        print("[*] No custom keys found, using default keys")

    # Extract encrypted payload
    encrypted = extract_encrypted_from_loader(raw)
    if encrypted:
        print("[*] Detected loader script; extracted _encrypted blob.")
        encrypted = normalize_blob(encrypted)
    else:
        print("[*] No embedded _encrypted assignment found; treating file as raw blob.")
        encrypted = normalize_blob(raw)

    try:
        payload = unpack(encrypted, key, iv)
    except Exception as e:
        print(f"[-] Failed to unpack payload: {e}")
        if custom_keys:
            print(
                "[-] Custom keys were extracted but decryption failed. The payload may be corrupted.")
        else:
            print(
                "[-] Default keys failed. This file may have been packed with custom keys.")
        sys.exit(1)

    btype = detect_binary_type(payload)
    digest = sha256_digest(payload)
    print(f"[+] Detected binary type: {btype}")
    print(f"[+] SHA256: {digest}")

    if "--skip-write" not in sys.argv:
        out_path.write_bytes(payload)
        print(f"[+] Written unpacked payload to {out_path}")
        if os.name != 'nt':
            out_path.chmod(0o755)
    else:
        print("[*] --skip-write provided; not writing output.")

    if "--print-type" in sys.argv:
        print(f"[i] Payload header (first 64 bytes): {payload[:64].hex()}")


if __name__ == "__main__":
    main()
