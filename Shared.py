import base64, json, os, struct, hashlib
from typing import Optional

# ---------- Base64 helpers ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# ---------- Framing: 4 byte len + payload ----------
def _recvall(sock, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def send_json(sock, obj) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_json(sock) -> Optional[dict]:
    hdr = _recvall(sock, 4)
    if not hdr:
        return None
    n = struct.unpack("!I", hdr)[0]
    payload = _recvall(sock, n)
    if not payload:
        return None
    return json.loads(payload.decode("utf-8"))

# ---------- Nonce/seq ----------
def randbytes(n: int) -> bytes:
    return os.urandom(n)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
