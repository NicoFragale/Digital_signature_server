import base64, json, os, struct, hashlib, time
from typing import Optional
from cryptography.hazmat.primitives.kdf.hkdf import HKDF 
#per derivare la chiave di sessione prende in input un segreto iniziale un salt e i metadati e deriviamo la chiave per la cifratura simmetrica 
from server import PROTO
from cryptography.hazmat.primitives import hashes

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

def hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """
    Derive a symmetric session key from a Diffie-Hellman shared secret using HKDF-SHA256.

    Args:
        shared_secret (bytes): Raw ECDH secret (e.g., X25519 .exchange()).
        salt (bytes): Per-session salt. Here we use Nc||Ns (client/server nonces) to ensure uniqueness
                      across sessions (defense-in-depth even if DH repeated, and for better extractor entropy).
        info (bytes): Context-binding string. Here we pass hash(transcript) to cryptographically bind the key
                      to the exact handshake parameters (protocol id, DH pubs, nonces), preventing cross-protocol reuse.
        length (int): Desired key length in bytes. Default 32 (suitable for AES-256-GCM).

    Returns:
        bytes: A pseudo-random key of 'length' bytes, suitable for symmetric crypto (e.g., AES-GCM).

    Security notes:
        - HKDF provides key-separation: changing either 'salt' or 'info' yields independent keys.
        - Using Nc||Ns as salt and hash(transcript) as info ties the key K to this specific session context.
        - Keep 'length' aligned with the cipher key size (32 bytes for AES-256-GCM).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info
    ).derive(shared_secret)


# Funzioni helper per OpSec.py

def _now_iso() -> str:
    """Ritorna l'istante corrente in formato ISO UTC (utile per created_at)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_transcript(client_pub: bytes, server_pub: bytes, Nc: bytes, Ns: bytes) -> bytes:
    """
    Build the handshake transcript that will be hashed and signed by the server to authenticate itself.

    The transcript binds the session to:
      - The protocol identity and version (PROTO),
      - The ephemeral DH public keys (client_pub, server_pub),
      - The nonces chosen by both sides (Nc, Ns).

    This defeats man-in-the-middle and cross-protocol attacks by ensuring the signature is valid
    only for this exact protocol/version and this exact pair of DH keys and nonces.

    Args:
        client_pub (bytes): Client's ephemeral X25519 public key (32 bytes, raw).
        server_pub (bytes): Server's ephemeral X25519 public key (32 bytes, raw).
        Nc (bytes): Client nonce (e.g., 16 bytes).
        Ns (bytes): Server nonce (e.g., 16 bytes).

    Returns:
        bytes: Canonical transcript bytes. These bytes should then be hashed (e.g., SHA-256)
               and signed with the server's long-term Ed25519 private key.

    Implementation note:
        We use a fixed field order to avoid ambiguity: PROTO | client_pub | server_pub | Nc | Ns.
        Because these fields have fixed size (except PROTO which is constant), this simple '|' join is safe here.
        For future extensibility, prefer length-prefixed or a structured encoding (e.g., CBOR).
    """
    # Fixed order to prevent ambiguity, and to match the verification side byte-for-byte
    return b"|".join([PROTO, client_pub, server_pub, Nc, Ns])
