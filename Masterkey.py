# Masterkey.py 
import os, json, base64, secrets
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_KEY_PATH = os.path.join("secrets", "master.key")          # legacy (chiaro, b64)
DEFAULT_KEY_JSON = os.path.join("secrets", "master.key.json")     # nuovo (cifrato)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1

def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)

def _chmod_600(path: str) -> None:
    try: os.chmod(path, 0o600)
    except Exception: pass

def _derive_kek(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    return Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode())

def _encrypt_masterkey(mk: bytes, passphrase: str) -> dict:
    salt = secrets.token_bytes(16)
    iv   = secrets.token_bytes(12)
    kek  = _derive_kek(passphrase, salt, 32)
    ct   = AESGCM(kek).encrypt(iv, mk, b"master.key.v1")
    return {
        "version": 1,
        "format": "aesgcm+scrypt",
        "kdf": {"alg": "scrypt", "salt": base64.b64encode(salt).decode(), "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        "enc": {"iv": base64.b64encode(iv).decode(), "ciphertext": base64.b64encode(ct).decode()}
    }

def _decrypt_masterkey(blob: dict, passphrase: str) -> bytes:
    salt = base64.b64decode(blob["kdf"]["salt"])
    n, r, p = blob["kdf"]["n"], blob["kdf"]["r"], blob["kdf"]["p"]
    iv  = base64.b64decode(blob["enc"]["iv"])
    ct  = base64.b64decode(blob["enc"]["ciphertext"])
    kek = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())
    mk  = AESGCM(kek).decrypt(iv, ct, b"master.key.v1")
    if len(mk) != 32:
        raise RuntimeError("Master key decifrata non è lunga 32 byte")
    return mk

def _read_legacy_key(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read().strip()
    mk = base64.b64decode(data, validate=True)
    if len(mk) != 32:
        raise RuntimeError("Master key legacy non è lunga 32 byte")
    return mk

def _write_json(path: str, obj: dict) -> None:
    _ensure_dir(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    _chmod_600(path)

def generate_or_migrate_and_encrypt(passphrase: str, remove_legacy: bool = True) -> str:
    """
    - Se esiste secrets/master.key (b64 chiaro), lo cifra in secrets/master.key.json.
    - Altrimenti genera 32B random e li cifra direttamente.
    """
    if os.path.exists(DEFAULT_KEY_JSON):
        return DEFAULT_KEY_JSON

    if os.path.exists(DEFAULT_KEY_PATH):
        mk = _read_legacy_key(DEFAULT_KEY_PATH)
    else:
        mk = secrets.token_bytes(32)

    blob = _encrypt_masterkey(mk, passphrase)
    _write_json(DEFAULT_KEY_JSON, blob)

    if os.path.exists(DEFAULT_KEY_PATH) and remove_legacy:
        try:
            with open(DEFAULT_KEY_PATH, "r+b") as f:
                b = f.read(); f.seek(0); f.write(b"\x00"*len(b)); f.truncate()
            os.remove(DEFAULT_KEY_PATH)
        except Exception:
            pass

    return DEFAULT_KEY_JSON

def load_master_key(passphrase: str) -> bytes:
    """Decifra e ritorna i 32 byte della master key (richiede JSON cifrato e passphrase)."""
    if not os.path.exists(DEFAULT_KEY_JSON):
        raise FileNotFoundError(f"{DEFAULT_KEY_JSON} non trovato.")
    with open(DEFAULT_KEY_JSON, "r", encoding="utf-8") as f:
        blob = json.load(f)
    if blob.get("version") != 1 or blob.get("format") != "aesgcm+scrypt":
        raise RuntimeError("Formato master.key.json non supportato")
    return _decrypt_masterkey(blob, passphrase)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python Masterkey.py <passphrase>")
        sys.exit(1)
    passphrase = sys.argv[1]
    path = generate_or_migrate_and_encrypt(passphrase)
    print(f"Master key cifrata salvata in {path}")
