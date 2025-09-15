import os, socket, json, logging, getpass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from Shared import b64e, b64d, send_json, recv_json, randbytes, sha256, hkdf_derive

SERVER_PUB_PATH = "keys/server_signing_public.pem"  # ricevuto offline
PROTO = b"DSS/1"
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

def run_client(host="127.0.0.1", port=5001):
    """
    Client DSS con handshake + autenticazione guidata dal server.
    Flusso:
      - Handshake con PFS e autenticazione del server (Ed25519).
      - Server invia subito AUTH_START (prompt di login) sul canale cifrato.
      - Client risponde con AUTH_USERNAME e poi AUTH_PASSWORD (ed eventuale AUTH_SET_NEWPASS).
      - Dopo AUTH_OK, puoi inviare API applicative (WHOAMI/CreateKeys/SignDoc/...).
    """
    # 1) Carica la chiave pubblica Ed25519 del server
    with open(SERVER_PUB_PATH, "rb") as f:
        server_signing_pub = load_pem_public_key(f.read())
    if not isinstance(server_signing_pub, Ed25519PublicKey):
        raise ValueError("La chiave pubblica del server deve essere Ed25519")

    # 2) TCP
    sock = socket.create_connection((host, port), timeout=10)

    try:
        # --- ClientHello ---
        client_eph = X25519PrivateKey.generate()
        client_pub_bytes = client_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        Nc = randbytes(16)
        send_json(sock, {"type": "ClientHello", "dh_pub": b64e(client_pub_bytes), "nonce": b64e(Nc)})
        logging.info("[client] Inviato ClientHello.")

        # --- ServerHello ---
        hello = recv_json(sock)
        assert hello and hello.get("type") == "ServerHello", "Handshake fallito (ServerHello)."
        server_pub_bytes = b64d(hello["dh_pub"])
        Ns = b64d(hello["nonce"])
        signature = b64d(hello["signature"])

        transcript = build_transcript(client_pub_bytes, server_pub_bytes, Nc, Ns)
        t_hash = sha256(transcript)
        server_signing_pub.verify(signature, t_hash)

        # --- Deriva chiave di sessione + conferme ---
        server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared = client_eph.exchange(server_pub)
        salt = Nc + Ns
        info = t_hash
        K = hkdf_derive(shared, salt, info, 32)  # AES-256
        aesgcm = AESGCM(K)

        # ClientFinish
        iv = os.urandom(12)
        aad = sha256(b"client-finish" + info)
        ct = aesgcm.encrypt(iv, b"OK-CF", aad)
        send_json(sock, {"type": "ClientFinish", "iv": b64e(iv), "ct": b64e(ct)})

        # ServerFinish
        sf = recv_json(sock)
        assert sf and sf.get("type") == "ServerFinish", "Handshake fallito (ServerFinish)."
        iv2 = b64d(sf["iv"]); ct2 = b64d(sf["ct"])
        aad2 = sha256(b"server-finish" + info)
        pt2 = aesgcm.decrypt(iv2, ct2, aad2)
        assert pt2 == b"OK-SF", "Conferma server errata."
        logging.info("[client] Handshake OK. Canale sicuro attivo.")

        # =========================
        #  FASE APPLICATIVA (AEAD)
        # =========================
        seq = 0  # seq crescente lato client (il server userà il proprio seq)

        def decrypt_reply(resp: dict) -> bytes:
            ivr = b64d(resp["iv"]); ctr = b64d(resp["ct"])
            aad_r = sha256(b"app|" + info + resp["seq"].to_bytes(8, "big") + b64d(resp["nonce"]))
            #print("Messaggio server: seq=", resp["seq"], " iv=", ivr, " nonce=", b64d(resp["nonce"]))
            return aesgcm.decrypt(ivr, ctr, aad_r)

        def send_app(plaintext: bytes):
            nonlocal seq
            seq += 1
            nonce_app = os.urandom(16)
            iv = os.urandom(12)
            aad_msg = sha256(b"app|" + info + seq.to_bytes(8, "big") + nonce_app)
            #print("Risposta client: seq=", seq, " iv=", iv, " nonce=", nonce_app)
            ct = aesgcm.encrypt(iv, plaintext, aad_msg)
            send_json(sock, {"seq": seq, "nonce": b64e(nonce_app), "iv": b64e(iv), "ct": b64e(ct)})
            resp = recv_json(sock)
            if not resp:
                logging.info("[client] Nessuna risposta (conn chiusa).")
                return None
            return decrypt_reply(resp)

        def send_op(obj: dict):
            rep = send_app(json.dumps(obj).encode("utf-8"))
            try:
                return None if rep is None else json.loads(rep.decode("utf-8"))
            except Exception:
                return None

        # === 0) RICEVI SUBITO IL PROMPT DEL SERVER (AUTH_START) ===
        first = recv_json(sock)
        if not first:
            logging.info("[client] Server ha chiuso.")
            return
        first_pt = decrypt_reply(first)
        try:
            first_obj = json.loads(first_pt.decode("utf-8"))
        except Exception:
            first_obj = None
        logging.info("[client] Primo messaggio server: %s", first_obj)
        if not first_obj or first_obj.get("op") != "AUTH_START":
            logging.info("[client] Il server non ha avviato AUTH_START; esco.")
            return

        # --- dialogo di autenticazione ---
        print("=== Autenticazione utente ===")
        user = input("Username: ").strip()
        print("username: %s" , user)
        if not user:
            logging.info("[client] Username mancante.")
            return

        r1 = send_op({"op": "AUTH_USERNAME", "username": user})
        logging.info("[client] AUTH_USERNAME -> %s", r1)
        if not r1 or r1.get("op") != "AUTH_NEED_PASSWORD":
            logging.info("[client] Flusso auth inatteso: %s", r1)
            return

        pwd = getpass.getpass("Password: ").strip()
        if not pwd:
            logging.info("[client] Password mancante.")
            return

        r2 = send_op({"op": "AUTH_PASSWORD", "password": pwd})
        logging.info("[client] AUTH_PASSWORD -> %s", r2)
        if not r2:
            logging.info("[client] Nessuna risposta dal server dopo AUTH_PASSWORD.")
            return

        if r2.get("op") == "AUTH_NEED_PWCHANGE":
            while True:
                newp = getpass.getpass("Nuova password: ").strip()
                conf = getpass.getpass("Conferma nuova password: ").strip()
                if not newp:
                    print("La nuova password non può essere vuota."); continue
                if newp != conf:
                    print("Le password non coincidono, riprova."); continue
                break
            r3 = send_op({"op": "AUTH_SET_NEWPASS", "username": user, "old_password": pwd, "new_password": newp})
            logging.info("[client] AUTH_SET_NEWPASS -> %s", r3)
            if not r3 or r3.get("op") != "AUTH_OK":
                logging.info("[client] Cambio password fallito."); return
            logging.info("[client] Cambio password OK. Autenticazione completata.")

        elif r2.get("op") == "AUTH_OK":
            logging.info("[client] Autenticazione completata.")

        elif r2.get("op") == "AUTH_TIMEOUT":
            logging.info("[client] Timeout autenticazione."); return

        else:
            logging.info("[client] Autenticazione fallita: %s", r2); return
        # =========================
        #  MENÙ OPERAZIONI OPSEC
        # =========================
        def menu():
            print("\n== Menu ==")
            print("1) CreateKeys")
            print("2) GetPublicKey")
            print("3) SignDoc")
            print("4) DeleteKeys")
            print("5) QUIT (chiudi server)")
            print("0) Esci client")
            return input("Scelta: ").strip()

        while True:
            choice = menu()

            if choice == "1":
                out = send_op({"op": "CreateKeys"})
                print("CreateKeys ->", out)

            elif choice == "2":
                tgt = input("target_user: ").strip()
                kid = input("key_id (opzionale, invio per saltare): ").strip() or None
                payload = {"op": "GetPublicKey", "target_user": tgt}
                if kid: payload["key_id"] = kid
                out = send_op(payload)
                print("GetPublicKey ->", out)

            elif choice == "3":
                path = input("Percorso del documento da firmare: ").strip()
                out = send_op({"op": "SignDoc", "doc_path": path})
                print("SignDoc ->", out)

            elif choice == "4":
                conf = input("Confermi cancellazione chiavi? (yes/NO): ").strip().lower()
                if conf == "yes":
                    out = send_op({"op": "DeleteKeys"})
                    print("DeleteKeys ->", out)
                    if out is None:
                        print("Connessione chiusa dal server.")
                        break
                    if out.get("session") == "closing":
                        print("Il server ha chiuso la sessione dopo DeleteKeys.")
                        break
                else:
                    print("Annullato.")

            elif choice == "5":
                # QUIT in chiaro sul canale cifrato; il server risponde BYE e chiude
                rep = send_app(b"QUIT")
                print("QUIT ->", None if rep is None else rep.decode(errors="ignore"))
                break  # usciamo dal loop, il server chiuderà la connessione

            elif choice == "0":
                print("Uscita client senza inviare QUIT.")
                break

            else:
                print("Scelta non valida.")

    finally:
        try:
            sock.close()
        except Exception:
            pass
        logging.info("[client] Chiuso.")


if __name__ == "__main__":
    run_client()
