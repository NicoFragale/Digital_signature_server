import os, json, time, base64, logging
from typing import Dict, Any
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYSTORE_DIR = "keystore"
MAX_FAILED = 5

logging.basicConfig(level=logging.INFO)

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def sanitize_username(u: str) -> str:
    u = (u or "").strip()
    safe = "".join(c for c in u if c.isalnum() or c in "-_.")
    if not safe: raise ValueError("username non valido")
    return safe

def user_dir(username: str) -> str:
    return os.path.join(KEYSTORE_DIR, sanitize_username(username))

def index_path(username: str) -> str:
    return os.path.join(user_dir(username), "index.json")

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def save_atomic(path: str, obj: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        import json; json.dump(obj, f, indent=2, sort_keys=True)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def load_index(username: str) -> Dict[str, Any]:
    p = index_path(username)
    if not os.path.exists(p): raise FileNotFoundError("UserNotFound")
    with open(p, "r", encoding="utf-8") as f:
        import json; return json.load(f)

def derive(password: str, salt: bytes, kdf_cfg: Dict[str, Any]) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=int(kdf_cfg.get("len", 32)),
        n=int(kdf_cfg.get("n", 2**14)),
        r=int(kdf_cfg.get("r", 8)),
        p=int(kdf_cfg.get("p", 1)),
    )
    return kdf.derive(password.encode("utf-8"))

def new_index_template(username: str) -> Dict[str, Any]:
    return {
        "username": sanitize_username(username),
        "kdf": {"alg":"scrypt","n":2**14,"r":8,"p":1,"len":32},
        "salt_b64": None, "hash_b64": None,
        "failed_attempts": 0, "locked": False, "needs_pw_change": True,
        "created_at": now_iso(), "last_auth_at": None, "last_auth_ip": None,
        "default_key_id": None, "registration_locked": False, "can_sign": True,
        "last_pw_change_at": None
    }

def create_user_offline(username: str, temp_password: str) -> Dict[str, Any]:
    username = sanitize_username(username)
    idx_path = index_path(username)
    if os.path.exists(idx_path):
        raise FileExistsError("AccountAlreadyExists")

    ensure_dir(user_dir(username))
    idx = new_index_template(username)

    salt = os.urandom(16)
    idx["salt_b64"] = base64.b64encode(salt).decode()
    idx["hash_b64"] = base64.b64encode(derive(temp_password, salt, idx["kdf"])).decode()

    save_atomic(idx_path, idx)
    logging.info("[accounts] Creato utente %s (index.json)", username)
    return {"username": username, "needs_pw_change": True}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Gestione account offline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # comando: create <username> <temp_password>
    ap_create = sub.add_parser("create", help="Crea un nuovo utente offline")
    ap_create.add_argument("username")
    ap_create.add_argument("temp_password")

    args = parser.parse_args()

    if args.cmd == "create":
        out = create_user_offline(args.username, args.temp_password)
        print(json.dumps(out, indent=2))
