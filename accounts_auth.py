import os, base64
from typing import Dict, Any
from cryptography.hazmat.primitives import constant_time
from account import (
    MAX_FAILED, sanitize_username, index_path, load_index, save_atomic,
    derive, now_iso
)

def verify_username(username: str, client_ip: str= None) -> Dict[str, Any]:
    username = sanitize_username(username)
    try:  
        p= index_path(username) 
        idx= load_index(username)
        return {"ok": True}
    except FileNotFoundError:
        return {"ok": False, "error": "UserNotFound"}

def verify_login(username: str, password: str, client_ip: str = None) -> Dict[str, Any]:
    username = sanitize_username(username)
    p = index_path(username)
    idx = load_index(username)

    if idx.get("locked"):
        return {"ok": False, "error": "Locked"}
    
    if not idx.get("salt_b64") or not idx.get("hash_b64"):
        return {"ok": False, "error": "NoCredentials"}

    salt = base64.b64decode(idx["salt_b64"])
    ref  = base64.b64decode(idx["hash_b64"])
    cand = derive(password, salt, idx.get("kdf", {}))
    ok = constant_time.bytes_eq(cand, ref)

    idx["last_auth_at"] = now_iso()
    idx["last_auth_ip"] = client_ip

    if not ok:
        idx["failed_attempts"] = int(idx.get("failed_attempts", 0)) + 1
        if idx["failed_attempts"] >= MAX_FAILED:
            idx["locked"] = True; err = "Locked"
        else:
            err = "BadCredentials"
        save_atomic(p, idx)
        return {"ok": False, "error": err, "remaining": max(0, MAX_FAILED - idx["failed_attempts"])}

    idx["failed_attempts"] = 0
    save_atomic(p, idx)
    return {"ok": True, "needs_pw_change": bool(idx.get("needs_pw_change", False))}

def change_password(username: str, old_password: str, new_password: str) -> Dict[str, Any]:
    username = sanitize_username(username)
    p = index_path(username)
    idx = load_index(username)
    if idx.get("locked"):
        return {"ok": False, "error": "Locked"}

    salt = base64.b64decode(idx["salt_b64"])
    ref  = base64.b64decode(idx["hash_b64"])
    if not constant_time.bytes_eq(derive(old_password, salt, idx.get("kdf", {})), ref):
        return {"ok": False, "error": "BadCredentials"}

    new_salt = os.urandom(16)
    new_hash = derive(new_password, new_salt, idx.get("kdf", {}))
    idx["salt_b64"] = base64.b64encode(new_salt).decode()
    idx["hash_b64"] = base64.b64encode(new_hash).decode()
    idx["needs_pw_change"] = False
    idx["failed_attempts"] = 0
    idx["last_pw_change_at"] = now_iso()
    save_atomic(p, idx)
    return {"ok": True}
