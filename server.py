import os, socket, json, sys # Librerie per utilizzare le utility di sistema, rete tcp, Json e gestione dei processi 
from typing import Tuple #Per annotare i ritorni di funzioni 
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey #chiavi per verificare e firmare, utili per l'autenticazione del server 
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey # chiavi effimere per lo scambio del segreto condiviso (g^b) visto che si richiede il PFS 
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat, load_pem_public_key, load_pem_private_key #serve a serializzare e deserializzare le chiavi pem per salvarle e leggerle 
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # per derivare la chiave di sessione prende in input un segreto iniziale un salt e i metadati e deriviamo la chiave per la cifratura simmetrica 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM #cifrario AES GCM (consigliato da gpt) utilizza l'AES (quindi utile per creare la chiave simmetrica con cui cifrare il traffico), a
#GCM (Galois/Counter Mode) trasforma la chiave simmetrica in un cifrario a flusso e integra un meccanismo di autenticazione perchè il CTR assicura confidenzialità, il campo di Galois viene utilizzato per creare un tag di autenticazione per assicurare integrità e autenticità

from shared import b64e, b64d, send_json, recv_json, randbytes, sha256 #libreria con le utility in cui abbiamo il framing (utilizzato per impostare l'inizio e fine del messaggio), il nonce random e dove calcoliamo gli hash 
#Directory per conservare le chiavi pubbliche e private del server 
KEYS_DIR = "keys"
PRIV_PATH = os.path.join(KEYS_DIR, "server_signing_private.pem")
PUB_PATH  = os.path.join(KEYS_DIR, "server_signing_public.pem")

PROTO = b"DSS/1"  # protocol id per il transcript -> cioè tutti i messaggi scambianti durante l'handshake
#questa è una funzione che controlla se la cartella keys esiste e se le chiavi sono presenti
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
#hkdf_derive: deriva il numero di byte di length da shared_secret utilizzando HKDF, il salt è la concatenazione di Nc e Ns (nonce randomici di 16 byte)
def hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(shared_secret)
#build_transcript: costruisce il transcript (che verrà hashto e firmato) per il messaggio di handshake, lega le chiavi e il nonce per evitare il MITM
def build_transcript(client_pub: bytes, server_pub: bytes, Nc: bytes, Ns: bytes) -> bytes:
    # Ordine fisso per prevenire ambiguità
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
