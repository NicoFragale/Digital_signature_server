import base64, json, os, struct, hashlib
from typing import Optional

# ---------- Base64 helpers ----------

def b64e(b: bytes) -> str:
    """
    Encode raw bytes into a Base64 ASCII string.

    Args:
        b (bytes): Input binary data.

    Returns:
        str: Base64-encoded string (ASCII).

    Usage:
        - Used to safely embed binary data (keys, nonces, ciphertexts)
          into JSON messages, since JSON supports only text.
    """
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    """
    Decode a Base64 ASCII string back into raw bytes.

    Args:
        s (str): Base64-encoded string.

    Returns:
        bytes: Original binary data.

    Usage:
        - Used to recover keys, nonces, IVs or ciphertexts from JSON
          fields encoded with `b64e`.
    """
    return base64.b64decode(s.encode("ascii"))

# ---------- Framing: 4 byte len + payload ----------

def _recvall(sock, n: int) -> Optional[bytes]:
    """
    Read exactly n bytes from a socket.

    This helper ensures that if `recv()` returns fewer bytes
    than requested (which often happens with TCP streams),
    it will continue reading until exactly `n` bytes are collected
    or the socket is closed.

    Args:
        sock: A connected socket object.
        n (int): Number of bytes to read.

    Returns:
        Optional[bytes]:
            - The collected bytes if successful.
            - None if the connection is closed before receiving `n` bytes.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send_json(sock, obj) -> None:
    """
    Serialize and send a JSON object with length-prefix framing.

    Each message is encoded as:
        [4-byte big-endian length][JSON payload]

    Args:
        sock: A connected socket object.
        obj: A Python object serializable into JSON (e.g. dict).

    Returns:
        None

    Usage:
        - Ensures that the receiver knows exactly how many bytes
          belong to the message, avoiding ambiguity when multiple
          JSON objects are sent over the same TCP connection.
    """
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_json(sock) -> Optional[dict]:
    """
    Receive and deserialize a JSON object from a socket.

    Reads the first 4 bytes to determine the message length,
    then reads exactly that many bytes as the JSON payload.

    Args:
        sock: A connected socket object.

    Returns:
        Optional[dict]:
            - The decoded Python object (typically a dict) if successful.
            - None if the socket closes unexpectedly.

    Usage:
        - Complements `send_json` to reliably exchange framed
          JSON messages over TCP.
    """
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
    """
    Generate n cryptographically secure random bytes.

    Args:
        n (int): Number of random bytes to produce.

    Returns:
        bytes: Random byte string of length n.

    Usage:
        - To generate nonces, IVs, session randomness, or unique tokens
          in cryptographic protocols.
    """
    return os.urandom(n)


def sha256(data: bytes) -> bytes:
    """
    Compute the SHA-256 hash of input data.

    Args:
        data (bytes): Arbitrary input data.

    Returns:
        bytes: 32-byte SHA-256 digest (raw bytes).

    Usage:
        - Used to hash transcripts, bind AEAD AAD, or derive context-bound values.
        - Returns raw bytes (not hex) for direct use in cryptographic operations.
    """
    return hashlib.sha256(data).digest()
