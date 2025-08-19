import os, socket, json, sys
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared import b64e, b64d, send_json, recv_json, randbytes, sha256

KEYS_DIR = "keys"
PRIV_PATH = os.path.join(KEYS_DIR, "server_signing_private.pem")
PUB_PATH  = os.path.join(KEYS_DIR, "server_signing_public.pem")

PROTO = b"DSS/1"  # protocol id per il transcript

def ensure_server_signing_keys() -> Tuple[Ed25519PrivateKey, bytes]:
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not os.path.exists(PRIV_PATH) or not os.path.exists(PUB_PATH):
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()

        priv_pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem  = pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        with open(PRIV_PATH, "wb") as f: f.write(priv_pem)
        with open(PUB_PATH,  "wb") as f: f.write(pub_pem)

        print("[server] Chiavi di firma generate.")
        print("[server] Copia sul client il file:", PUB_PATH)
    else:
        print("[server] Uso chiavi di firma esistenti.")

    with open(PRIV_PATH, "rb") as f:
        sk = load_pem_private_key(f.read(), password=None)
    with open(PUB_PATH, "rb") as f:
        server_pub_pem = f.read()

    return sk, server_pub_pem

def hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(shared_secret)

def build_transcript(client_pub: bytes, server_pub: bytes, Nc: bytes, Ns: bytes) -> bytes:
    # Ordine fisso per prevenire ambiguità
    return b"|".join([PROTO, client_pub, server_pub, Nc, Ns])

def run_server(host="127.0.0.1", port=5001):
    sk_sign, server_pub_pem = ensure_server_signing_keys()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[server] In ascolto su {host}:{port}")
    try:
        while True:
            conn, addr = sock.accept()
            print("[server] Connessione:", addr)
            try:
                # --- 1) Ricevi ClientHello ---
                hello = recv_json(conn)
                if not hello or hello.get("type") != "ClientHello":
                    conn.close(); continue

                client_pub_bytes = b64d(hello["dh_pub"])
                Nc = b64d(hello["nonce"])
                client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)

                # --- 2) Genera ECDH effimero e rispondi con ServerHello firmato ---
                server_eph = X25519PrivateKey.generate()
                server_pub_bytes = server_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                Ns = randbytes(16)

                # Shared secret
                shared = server_eph.exchange(client_pub)

                transcript = build_transcript(client_pub_bytes, server_pub_bytes, Nc, Ns)
                t_hash = sha256(transcript)
                signature = sk_sign.sign(t_hash)

                reply = {
                    "type": "ServerHello",
                    "dh_pub": b64e(server_pub_bytes),
                    "nonce": b64e(Ns),
                    "signature": b64e(signature),
                    # opzionale: non serve inviare la chiave pubblica di firma; il client la ha offline
                }
                send_json(conn, reply)

                # --- 3) Deriva chiavi sessione e conferma chiave ---
                # K = HKDF(shared, salt=Nc||Ns, info=hash(transcript))
                salt = Nc + Ns
                info = t_hash
                K = hkdf_derive(shared, salt, info, 32)   # 256 bit
                aesgcm = AESGCM(K)

                # Attesa ClientFinish (AEAD conferma lato client)
                cf = recv_json(conn)
                if not cf or cf.get("type") != "ClientFinish":
                    conn.close(); continue

                iv = b64d(cf["iv"])
                ct = b64d(cf["ct"])
                aad = sha256(b"client-finish" + info)
                try:
                    pt = aesgcm.decrypt(iv, ct, aad)
                    if pt != b"OK-CF":
                        raise ValueError("bad confirm")
                except Exception:
                    print("[server] Conferma client fallita, chiudo.")
                    conn.close(); continue

                # Invia ServerFinish
                iv2 = os.urandom(12)
                aad2 = sha256(b"server-finish" + info)
                ct2 = aesgcm.encrypt(iv2, b"OK-SF", aad2)
                send_json(conn, {"type": "ServerFinish", "iv": b64e(iv2), "ct": b64e(ct2)})

                print("[server] Handshake completato. Canale sicuro attivo.")

                # =========================
                #  MESSAGGI APPLICATIVI
                # =========================
                last_seq = 0
                seen_nonces = set()
                while True:
                    msg = recv_json(conn)
                    if not msg:
                        break

                    seq = msg.get("seq", 0)
                    if seq <= last_seq:
                        # anti-replay (seq non crescente)
                        continue
                    last_seq = seq

                    nonce_app = b64d(msg["nonce"])
                    if nonce_app in seen_nonces:
                        continue
                    seen_nonces.add(nonce_app)

                    iv = b64d(msg["iv"]); ct = b64d(msg["ct"])
                    aad = sha256(b"app|" + info + seq.to_bytes(8, "big") + nonce_app)
                    try:
                        plaintext = AESGCM(K).decrypt(iv, ct, aad)
                    except Exception:
                        print("[server] AEAD decrypt fallita.")
                        continue

                    # Esempio: echo sicuro
                    if plaintext == b"PING":
                        resp = b"PONG"
                    elif plaintext == b"QUIT":
                        resp = b"BYE"; 
                        # invio risposta e poi chiudo
                    else:
                        # placeholder per integrazione: Login/SignDoc/etc
                        resp = b"ECHO:" + plaintext

                    ivr = os.urandom(12)
                    ctr = AESGCM(K).encrypt(ivr, resp, aad)
                    send_json(conn, {"seq": seq, "iv": b64e(ivr), "ct": b64e(ctr), "nonce": b64e(nonce_app)})

                    if plaintext == b"QUIT":
                        break

            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\n[server] Stop richiesto.")
    finally:
        sock.close()
        print("[server] Chiuso.")
        
if __name__ == "__main__":
    run_server()
