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
    """
    Deriva una chiave simmetrica a partire da un segreto condiviso (es. da Diffie-Hellman X25519),
    utilizzando HKDF con SHA-256 come funzione di derivazione.

    Args:
        shared_secret (bytes): segreto grezzo ottenuto dallo scambio ECDH (X25519.exchange()).
        salt (bytes): valore casuale/salt per garantire unicità delle chiavi. 
                      In questo protocollo è Nc||Ns (concatenazione dei nonce del client e del server).
        info (bytes): stringa di contesto che lega la chiave a un protocollo/versione specifico.
                      Qui si usa hash(transcript).
        length (int): lunghezza della chiave in byte (default 32 = 256 bit per AES-256-GCM).

    Returns:
        bytes: chiave simmetrica derivata, da usare per cifratura/autenticazione.

    Note:
        - Usare HKDF garantisce che la chiave derivata sia uniforme e crittograficamente sicura.
        - L'inclusione di salt e info assicura separazione tra sessioni diverse e previene attacchi cross-protocol.
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(shared_secret)


def build_transcript(client_pub: bytes, server_pub: bytes, Nc: bytes, Ns: bytes) -> bytes:
    """
    Costruisce il transcript dell'handshake, che sarà hashato e firmato dal server (e verificato dal client).
    Il transcript lega crittograficamente la sessione ai parametri negoziati,
    prevenendo attacchi di tipo man-in-the-middle e cross-protocol.

    Args:
        client_pub (bytes): chiave pubblica effimera X25519 del client (32 byte).
        server_pub (bytes): chiave pubblica effimera X25519 del server (32 byte).
        Nc (bytes): nonce casuale generato dal client (16 byte).
        Ns (bytes): nonce casuale generato dal server (16 byte).

    Returns:
        bytes: transcript canonico nella forma:
               PROTO | client_pub | server_pub | Nc | Ns

    Note:
        - PROTO è un identificatore costante del protocollo/versione (es. b"DSS/1").
        - L'ordine e il formato dei campi devono essere identici lato client e lato server,
          altrimenti la verifica della firma e la derivazione della chiave falliscono.
    """
    return b"|".join([PROTO, client_pub, server_pub, Nc, Ns])


def run_client(host="127.0.0.1", port=5001):
    """
    Avvia il client DSS, stabilisce un canale sicuro col server e invia esempi di messaggi applicativi.

    Flusso:
      1) Carica la chiave pubblica Ed25519 del server (distribuita offline).
      2) Apre una connessione TCP al server.
      3) Esegue l'handshake con PFS e autenticazione del server:
         - Invia ClientHello: X25519 effimera del client + nonce Nc.
         - Riceve ServerHello: X25519 effimera del server + nonce Ns + firma Ed25519 sul transcript.
         - Verifica la firma con la chiave pubblica del server.
         - Deriva la chiave di sessione K con HKDF(shared, salt=Nc||Ns, info=hash(transcript)).
         - Scambia ClientFinish/ServerFinish (AEAD) per confermare la chiave.
      4) Entra nella fase applicativa: invia messaggi cifrati/autenticati (AES-GCM) con anti-replay
         (seq crescente + nonce unico), e stampa le risposte del server.

    Parametri:
        host (str): indirizzo del server.
        port (int): porta del server.
    """
    # 1) Carica chiave pubblica di firma del server (distribuita offline)
    with open(SERVER_PUB_PATH, "rb") as f:
        server_signing_pub = load_pem_public_key(f.read())
    if not isinstance(server_signing_pub, Ed25519PublicKey):
        raise ValueError("La chiave pubblica del server deve essere Ed25519")

    # 2) Crea socket e stabilisce la connessione TCP
    sock = socket.create_connection((host, port), timeout=10)

    try:
        # --- ClientHello ---
        # Genera X25519 effimera del client e un nonce Nc per questa sessione
        client_eph = X25519PrivateKey.generate()
        client_pub_bytes = client_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        Nc = randbytes(16)

        # Invia ClientHello con chiave pubblica DH (g^a) e nonce (Nc)
        send_json(sock, {"type": "ClientHello", "dh_pub": b64e(client_pub_bytes), "nonce": b64e(Nc)})
        print("[client] Inviato ClientHello con chiave pubblica e nonce.", send_json)
        
        # --- Ricevi ServerHello ---
        hello = recv_json(sock) #riceve il messaggio di ServerHello
        print("[client] Ricevuto ServerHello:", hello)
        assert hello and hello.get("type") == "ServerHello", "Handshake fallito (ServerHello)." # verifica che il messaggio sia corretto
        
        # Estrae la pubblica DH del server (g^b), il nonce Ns e la firma Ed25519
        server_pub_bytes = b64d(hello["dh_pub"])
        Ns = b64d(hello["nonce"])
        signature = b64d(hello["signature"])

        # Verifica firma del server sul transcript (PROTO|g^a|g^b|Nc|Ns)
        transcript = build_transcript(client_pub_bytes, server_pub_bytes, Nc, Ns)
        t_hash = sha256(transcript)
        server_signing_pub.verify(signature, t_hash)

        # --- Deriva chiavi e conferma ---
        # Calcola shared secret DH: (g^b)^a e deriva la chiave di sessione K
        server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared = client_eph.exchange(server_pub)

        salt = Nc + Ns                # per-session salt
        info = t_hash                 # context binding: hash del transcript
        K = hkdf_derive(shared, salt, info, 32)  # 32 byte = AES-256
        aesgcm = AESGCM(K)

        # Invia ClientFinish (AEAD conferma) per dimostrare conoscenza di K
        iv = os.urandom(12)
        aad = sha256(b"client-finish" + info)
        ct = aesgcm.encrypt(iv, b"OK-CF", aad)
        send_json(sock, {"type": "ClientFinish", "iv": b64e(iv), "ct": b64e(ct)})
        print("[client] Inviato ClientFinish.", send_json)
        
        # Attendi ServerFinish e verifica
        sf = recv_json(sock)
        print("[client] Ricevuto ServerFinish:", sf)
        assert sf and sf.get("type") == "ServerFinish", "Handshake fallito (ServerFinish)."
        iv2 = b64d(sf["iv"]); ct2 = b64d(sf["ct"])
        aad2 = sha256(b"server-finish" + info)
        pt2 = aesgcm.decrypt(iv2, ct2, aad2)
        assert pt2 == b"OK-SF", "Conferma server errata."

        print("[client] Handshake OK. Canale sicuro attivo.")

        # =========================
        #  MESSAGGI APPLICATIVI
        # =========================
        seq = 0 # numero di sequenza crescente per anti-replay

        def send_app(plaintext: bytes):
            """
            Invia un messaggio applicativo cifrato/autenticato (AES-GCM) e stampa la risposta.

            - Usa seq crescente e nonce_app casuale per anti-replay.
            - AAD lega il messaggio al contesto (proto/transcript), seq e nonce.
            """
            nonlocal seq
            seq += 1

            nonce_app = os.urandom(16)
            iv = os.urandom(12)
            aad = sha256(b"app|" + info + seq.to_bytes(8, "big") + nonce_app)
            
            # Cifra il payload applicativo
            ct = AESGCM(K).encrypt(iv, plaintext, aad)
            
            # Invia al server
            send_json(sock, {
                "seq": seq,
                "nonce": b64e(nonce_app),
                "iv": b64e(iv),
                "ct": b64e(ct)
            })

            # Attende la risposta e la decifra
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
