import os, socket
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared import b64e, b64d, send_json, recv_json, randbytes, sha256

SERVER_PUB_PATH = "keys/server_signing_public.pem"  # ricevuto offline
PROTO = b"DSS/1"

def hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(shared_secret)

def build_transcript(client_pub: bytes, server_pub: bytes, Nc: bytes, Ns: bytes) -> bytes:
    return b"|".join([PROTO, client_pub, server_pub, Nc, Ns])

def run_client(host="127.0.0.1", port=5001):
    # 1) Carica chiave pubblica di firma del server (distribuita offline)
    with open(SERVER_PUB_PATH, "rb") as f:
        server_signing_pub = load_pem_public_key(f.read())
    if not isinstance(server_signing_pub, Ed25519PublicKey):
        raise ValueError("La chiave pubblica del server deve essere Ed25519")

    # 2) Crea socket
    sock = socket.create_connection((host, port), timeout=10)

    try:
        # --- ClientHello ---
        client_eph = X25519PrivateKey.generate()
        client_pub_bytes = client_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        Nc = randbytes(16)
        send_json(sock, {"type": "ClientHello", "dh_pub": b64e(client_pub_bytes), "nonce": b64e(Nc)})

        # --- Ricevi ServerHello ---
        hello = recv_json(sock)
        assert hello and hello.get("type") == "ServerHello", "Handshake fallito (ServerHello)."
        server_pub_bytes = b64d(hello["dh_pub"])
        Ns = b64d(hello["nonce"])
        signature = b64d(hello["signature"])

        # Verifica firma del server sul transcript
        transcript = build_transcript(client_pub_bytes, server_pub_bytes, Nc, Ns)
        t_hash = sha256(transcript)
        server_signing_pub.verify(signature, t_hash)

        # --- Deriva chiavi e conferma ---
        server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared = client_eph.exchange(server_pub)

        salt = Nc + Ns
        info = t_hash
        K = hkdf_derive(shared, salt, info, 32)
        aesgcm = AESGCM(K)

        # Invia ClientFinish (AEAD conferma)
        iv = os.urandom(12)
        aad = sha256(b"client-finish" + info)
        ct = aesgcm.encrypt(iv, b"OK-CF", aad)
        send_json(sock, {"type": "ClientFinish", "iv": b64e(iv), "ct": b64e(ct)})

        # Attendi ServerFinish
        sf = recv_json(sock)
        assert sf and sf.get("type") == "ServerFinish", "Handshake fallito (ServerFinish)."
        iv2 = b64d(sf["iv"]); ct2 = b64d(sf["ct"])
        aad2 = sha256(b"server-finish" + info)
        pt2 = aesgcm.decrypt(iv2, ct2, aad2)
        assert pt2 == b"OK-SF", "Conferma server errata."

        print("[client] Handshake OK. Canale sicuro attivo.")

        # =========================
        #  MESSAGGI APPLICATIVI
        # =========================
        seq = 0
        def send_app(plaintext: bytes):
            nonlocal seq
            seq += 1
            nonce_app = os.urandom(16)
            iv = os.urandom(12)
            aad = sha256(b"app|" + info + seq.to_bytes(8, "big") + nonce_app)
            ct = AESGCM(K).encrypt(iv, plaintext, aad)
            send_json(sock, {"seq": seq, "nonce": b64e(nonce_app), "iv": b64e(iv), "ct": b64e(ct)})
            resp = recv_json(sock)
            if not resp:
                print("[client] Nessuna risposta (conn chiusa).")
                return
            ivr = b64d(resp["iv"]); ctr = b64d(resp["ct"])
            aad_r = sha256(b"app|" + info + resp["seq"].to_bytes(8, "big") + b64d(resp["nonce"]))
            reply = AESGCM(K).decrypt(ivr, ctr, aad_r)
            print("[client] Risposta:", reply.decode(errors="ignore"))

        # Esempi:
        send_app(b"PING")
        send_app(b"HELLO DSS")
        send_app(b"QUIT")  # chiede al server di chiudere la sessione
    finally:
        sock.close()
        print("[client] Chiuso.")

if __name__ == "__main__":
    run_client()
