import os, socket, json, sys # Librerie per utilizzare le utility di sistema, rete tcp, Json e gestione dei processi 
from typing import Tuple #Per annotare i ritorni di funzioni 
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey 
#chiavi per verificare e firmare, utili per l'autenticazione del server 

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey 
#chiavi effimere per lo scambio del segreto condiviso (g^b) visto che si richiede il PFS 

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat, load_pem_public_key, load_pem_private_key 
#serve a serializzare e deserializzare le chiavi pem per salvarle e leggerle 

from cryptography.hazmat.primitives.kdf.hkdf import HKDF 
#per derivare la chiave di sessione prende in input un segreto iniziale un salt e i metadati e deriviamo la chiave per la cifratura simmetrica 

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM 
#cifrario AES GCM (consigliato da gpt) utilizza l'AES (quindi utile per creare la chiave simmetrica con cui cifrare il traffico), a
#GCM (Galois/Counter Mode) trasforma la chiave simmetrica in un cifrario a flusso e integra un meccanismo di autenticazione perchè il CTR assicura confidenzialità, il campo di Galois viene utilizzato per creare un tag di autenticazione per assicurare integrità e autenticità

from shared import b64e, b64d, send_json, recv_json, randbytes, sha256 #libreria con le utility in cui abbiamo il framing (utilizzato per impostare l'inizio e fine del messaggio), il nonce random e dove calcoliamo gli hash 
#Directory per conservare le chiavi pubbliche e private del server 



KEYS_DIR = "keys"
PRIV_PATH = os.path.join(KEYS_DIR, "server_signing_private.pem")
PUB_PATH  = os.path.join(KEYS_DIR, "server_signing_public.pem")

PROTO = b"DSS/1"  # protocol id per il transcript -> cioè tutti i messaggi scambianti durante l'handshake




def ensure_server_signing_keys() -> Tuple[Ed25519PrivateKey, bytes]:
    """
    Ensure that the server's long-term Ed25519 signing key pair exists.

    - If the private/public key files are missing, generate a new Ed25519 key pair,
      serialize them in PEM format, and save them under KEYS_DIR.
    - If the key files already exist, reuse them.
    - Always return:
        * The server's private Ed25519 key (as an object).
        * The server's public key in PEM format (bytes), suitable for distribution to clients.

    Returns:
        Tuple[Ed25519PrivateKey, bytes]: (private_key_object, public_key_pem_bytes)
    """

    # Ensure the directory for key storage exists
    os.makedirs(KEYS_DIR, exist_ok=True)

    # If private or public key files are missing, generate a new key pair
    if not os.path.exists(PRIV_PATH) or not os.path.exists(PUB_PATH):
        # Generate new Ed25519 private key and its corresponding public key
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()

        # Serialize the private key in PEM (PKCS#8, unencrypted)
        priv_pem = sk.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )

        # Serialize the public key in PEM (SubjectPublicKeyInfo)
        pub_pem = pk.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )

        # Save both keys to disk
        with open(PRIV_PATH, "wb") as f:
            f.write(priv_pem)
        with open(PUB_PATH, "wb") as f:
            f.write(pub_pem)

        print("[server] Chiavi di firma generate.")
        print("[server] Copia sul client il file:", PUB_PATH)
    else:
        # Keys already exist on disk, so reuse them
        print("[server] Uso chiavi di firma esistenti.")

    # Load private key object and public key bytes from files
    with open(PRIV_PATH, "rb") as f:
        sk = load_pem_private_key(f.read(), password=None)
    with open(PUB_PATH, "rb") as f:
        server_pub_pem = f.read()

    return sk, server_pub_pem


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


#run_server: avvia il server e gestisce le connessioni in arrivo
def run_server(host="127.0.0.1", port=5001):
    sk_sign, server_pub_pem = ensure_server_signing_keys() #ci assicuriamo che ci siano le chiavi 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #si costruisce il socket 
    sock.bind((host, port))
    sock.listen(5)
    print(f"[server] In ascolto su {host}:{port}")
    try:
        while True:
            conn, addr = sock.accept()
            print("[server] Connessione:", addr)
            try:
                # --- 1) Ricevi ClientHello ---
                hello = recv_json(conn) #attende il ClientHello per iniziare l' handshake 
                print("[server] Ricevuto ClientHello:", hello)
                if not hello or hello.get("type") != "ClientHello":
                    conn.close(); continue

                client_pub_bytes = b64d(hello["dh_pub"]) #estrae la chiave pubblica del client (g^a) oltre al suo nonce (Nc)
                Nc = b64d(hello["nonce"])
                client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)

                # --- 2) Genera ECDH effimero e rispondi con ServerHello firmato ---
                server_eph = X25519PrivateKey.generate() #genera la chiave effimera del server (g^b)
                server_pub_bytes = server_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                Ns = randbytes(16) #genera il nonce del server (Ns)

                # Shared secret
                shared = server_eph.exchange(client_pub) # calcola il segreto condiviso

                #Costruiamo il transcript, lo hashiamo e lo firimiamo per evitare il MITM
                transcript = build_transcript(client_pub_bytes, server_pub_bytes, Nc, Ns) 
                t_hash = sha256(transcript)
                signature = sk_sign.sign(t_hash)

                # Invia la risposta al client, chiave pubblica, Ns e firma
                reply = {
                    "type": "ServerHello",
                    "dh_pub": b64e(server_pub_bytes),
                    "nonce": b64e(Ns),
                    "signature": b64e(signature),
                    # opzionale: non serve inviare la chiave pubblica di firma; il client la ha offline
                }
                send_json(conn, reply)
                print("[server] Inviato ServerHello:", reply)
                # --- 3) Deriva chiavi sessione e conferma chiave ---
                # Serve per confermare che il client ha ricevuto la stessa chiave del server 
                # K = HKDF(shared, salt=Nc||Ns, info=hash(transcript))
                salt = Nc + Ns
                info = t_hash
                K = hkdf_derive(shared, salt, info, 32)   # 256 bit
                aesgcm = AESGCM(K)

                # Attesa ClientFinish (AEAD conferma lato client)
                cf = recv_json(conn)
                print("[server] Ricevuto ClientFinish:", cf)
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
                print(send_json)
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
                        print("[server] Messaggio applicativo ricevuto:", plaintext)
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
