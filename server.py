import os, socket, json, sys # Librerie per utilizzare le utility di sistema, rete tcp, Json e gestione dei processi 
from typing import Tuple #Per annotare i ritorni di funzioni 
import logging 

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey 
#chiavi per verificare e firmare, utili per l'autenticazione del server 

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey 
#chiavi effimere per lo scambio del segreto condiviso (g^b) visto che si richiede il PFS 

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat, load_pem_public_key, load_pem_private_key 
#serve a serializzare e deserializzare le chiavi pem per salvarle e leggerle 

from cryptography.hazmat.primitives.ciphers.aead import AESGCM 
#cifrario AES GCM (consigliato da gpt) utilizza l'AES (quindi utile per creare la chiave simmetrica con cui cifrare il traffico), a
#GCM (Galois/Counter Mode) trasforma la chiave simmetrica in un cifrario a flusso e integra un meccanismo di autenticazione perchè il CTR assicura confidenzialità, il campo di Galois viene utilizzato per creare un tag di autenticazione per assicurare integrità e autenticità

from Shared import b64e, b64d, send_json, recv_json, randbytes, sha256, build_transcript, hkdf_derive #libreria con le utility in cui abbiamo il framing (utilizzato per impostare l'inizio e fine del messaggio), il nonce random e dove calcoliamo gli hash 
#Directory per conservare le chiavi pubbliche e private del server 



KEYS_DIR = "keys"
PRIV_PATH = os.path.join(KEYS_DIR, "server_signing_private.pem")
PUB_PATH  = os.path.join(KEYS_DIR, "server_signing_public.pem")

PROTO = b"DSS/1"  # protocol id per il transcript -> cioè tutti i messaggi scambianti durante l'handshake

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

        logging.info("[server] Chiavi di firma generate.")
        logging.info("[server] Copia sul client il file:", PUB_PATH)
    else:
        # Keys already exist on disk, so reuse them
        logging.info("[server] Uso chiavi di firma esistenti.")

    # Load private key object and public key bytes from files
    with open(PRIV_PATH, "rb") as f:
        sk = load_pem_private_key(f.read(), password=None)
    with open(PUB_PATH, "rb") as f:
        server_pub_pem = f.read()

    return sk, server_pub_pem


def run_server(host="127.0.0.1", port=5001):
    """
    Avvia il server DSS e gestisce connessioni sicure con i client.

    Funzioni principali:
    1. Carica o genera la coppia di chiavi Ed25519 del server (per autenticazione).
    2. Crea un socket TCP in ascolto sul `host:port`.
    3. Per ogni client:
        - Esegue l'handshake sicuro:
            * Riceve ClientHello (chiave DH effimera e nonce Nc).
            * Genera chiave DH effimera del server + nonce Ns.
            * Calcola shared secret via X25519.
            * Costruisce il transcript, ne calcola hash e firma con Ed25519.
            * Invia ServerHello (chiave DH, nonce, firma).
            * Deriva chiave di sessione K con HKDF(shared, Nc||Ns, hash(transcript)).
            * Riceve ClientFinish cifrato (verifica che il client conosce K).
            * Invia ServerFinish cifrato (conferma lato server).
        - Se handshake completato, entra nel loop di messaggi applicativi cifrati:
            * Decifra messaggi usando AES-GCM con AAD legata a transcript, seq, nonce.
            * Applica controlli anti-replay (seq crescente, nonce unico).
            * Esegue logica applicativa (PING→PONG, QUIT→BYE, echo).
            * Risponde cifrando con la stessa chiave K.
    4. Supporta interruzione con CTRL+C e chiusura ordinata del socket.

    Parametri:
        host (str): indirizzo IP su cui ascoltare (default: 127.0.0.1).
        port (int): porta TCP su cui ascoltare (default: 5001).
    """

    # 1) Assicuriamoci che le chiavi Ed25519 del server esistano
    sk_sign, server_pub_pem = ensure_server_signing_keys()

    # 2) Creiamo il socket TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    logging.info(f"[server] In ascolto su {host}:{port}")

    try:
        while True:
            # 3) Accetta un client
            conn, addr = sock.accept()
            logging.info("[server] Connessione:", addr)
            try:

                # --- HANDSHAKE ---
                # Riceve ClientHello: deve contenere la chiave DH effimera e un nonce Nc
                hello = recv_json(conn)
                logging.info("[server] Ricevuto ClientHello:", hello)
                if not hello or hello.get("type") != "ClientHello":
                    conn.close(); continue

                client_pub_bytes = b64d(hello["dh_pub"])   # chiave pubblica effimera del client (g^a)
                Nc = b64d(hello["nonce"])                  # nonce del client
                client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)

                # Genera chiave DH effimera del server (g^b) e nonce Ns
                server_eph = X25519PrivateKey.generate()
                server_pub_bytes = server_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                Ns = randbytes(16)

                # Calcola shared secret con X25519: (g^a)^b
                shared = server_eph.exchange(client_pub)

                # Costruisce transcript, lo hasha e lo firma con Ed25519
                transcript = build_transcript(client_pub_bytes, server_pub_bytes, Nc, Ns)
                t_hash = sha256(transcript)
                signature = sk_sign.sign(t_hash)

                # Invia ServerHello con chiave DH del server, nonce Ns e firma
                reply = {
                    "type": "ServerHello",
                    "dh_pub": b64e(server_pub_bytes),
                    "nonce": b64e(Ns),
                    "signature": b64e(signature),
                    # Non serve inviare la chiave pubblica di firma (il client la ha offline)
                }
                send_json(conn, reply)
                logging.info("[server] Inviato ServerHello:", reply)

                # Deriva chiave di sessione con HKDF(shared, salt=Nc||Ns, info=hash(transcript))
                salt = Nc + Ns
                info = t_hash
                K = hkdf_derive(shared, salt, info, 32)   # AES-256
                aesgcm = AESGCM(K)

                # Riceve ClientFinish cifrato: serve a confermare che il client conosce K
                cf = recv_json(conn)
                logging.info("[server] Ricevuto ClientFinish:", cf)
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
                    logging.info("[server] Conferma client fallita, chiudo.")
                    conn.close(); continue

                # Invia ServerFinish: conferma lato server della chiave
                iv2 = os.urandom(12)
                aad2 = sha256(b"server-finish" + info)
                ct2 = aesgcm.encrypt(iv2, b"OK-SF", aad2)
                send_json(conn, {"type": "ServerFinish", "iv": b64e(iv2), "ct": b64e(ct2)})
                logging.info("[server] Handshake completato. Canale sicuro attivo.")

                # --- LOOP APPLICATIVO ---
                last_seq = 0           # ultimo seq visto (per controllare ordine)
                seen_nonces = set()    # nonces già usati (per anti-replay)

                while True:
                    msg = recv_json(conn)
                    if not msg:
                        break

                    # Controllo ordine dei messaggi (seq deve crescere)
                    seq = msg.get("seq", 0)
                    if seq <= last_seq:
                        continue
                    last_seq = seq

                    # Controllo unicità del nonce
                    nonce_app = b64d(msg["nonce"])
                    if nonce_app in seen_nonces:
                        continue
                    seen_nonces.add(nonce_app)

                    # Decifra il messaggio applicativo con AES-GCM
                    iv = b64d(msg["iv"]); ct = b64d(msg["ct"])
                    aad = sha256(b"app|" + info + seq.to_bytes(8, "big") + nonce_app)
                    try:
                        plaintext = AESGCM(K).decrypt(iv, ct, aad)
                        logging.info("[server] Messaggio applicativo ricevuto:", plaintext)
                    except Exception:
                        logging.info("[server] AEAD decrypt fallita.")
                        continue

                    # Logica applicativa base (esempio)
                    if plaintext == b"PING":
                        resp = b"PONG"
                    elif plaintext == b"QUIT":
                        resp = b"BYE"
                        # invio risposta e poi chiudo
                    else:
                        # placeholder: qui andranno Login, CreateKeys, SignDoc, ecc.
                        resp = b"ECHO:" + plaintext

                    # Invia la risposta cifrata
                    ivr = os.urandom(12)
                    ctr = AESGCM(K).encrypt(ivr, resp, aad)
                    send_json(conn, {
                        "seq": seq,
                        "iv": b64e(ivr),
                        "ct": b64e(ctr),
                        "nonce": b64e(nonce_app)
                    })

                    # Se il messaggio era QUIT, chiudiamo la connessione
                    if plaintext == b"QUIT":
                        break

            finally:
                # Assicura la chiusura della connessione client
                conn.close()

    except KeyboardInterrupt:
        logging.info("\n[server] Stop richiesto.")
    finally:
        # Chiude il socket principale
        sock.close()
        logging.info("[server] Chiuso.")


if __name__ == "__main__":
    run_server()
