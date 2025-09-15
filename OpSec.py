# Per effettuare queste operazioni prima devi essere autenticato, ad oggi 25 Agosto ancora da fare questa parte. 
# Ogni richiesta è quindi associata ad un utente, GetPublicKey ritorna la chiave di un altro utente Y.
# Le chiavi private devono rimanere cifrate!

# ====== IMPORT NECESSARI ======
import os                            # gestione filesystem e variabili d'ambiente
import json                          # salvataggio/lettura dei metadati in formato JSON
import time                          # timestamp ISO e data per il key_id
import base64                        # codifica/decodifica base64 per salvare byte binari in JSON
import secrets                       # generazione sicura di nonce/identificatori
import hashlib
import logging

from Masterkey import load_master_key                       # logging strutturato al posto di print

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

from typing import Dict, Any, Optional         # annotazioni di tipo (facoltative ma utili)

from cryptography.hazmat.primitives import serialization  # per serializzare chiavi in formato Raw
from cryptography.hazmat.primitives.asymmetric import ed25519  # per generare/gestire chiavi Ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # per cifrare a riposo la privata con AEAD (AES-GCM)
from Shared import b64e, _now_iso

# ====== COSTANTI DI CONFIGURAZIONE ======
KEYSTORE_DIR = "keystore"            # radice del keystore su disco, per-utente (keystore/<username>/)
MASTER_KEY_ENV = "DSS_MASTER_KEY"
DEFAULT_KEY_PATH = os.path.join("secrets", "master.key")

# ====== HELPER DI BASE per le funzioni principali ======

def _user_dir(username: str) -> str:
    """Ritorna il percorso della cartella dell'utente dentro il keystore."""
    return os.path.join(KEYSTORE_DIR, username)

def _index_path(username: str) -> str:
    """Percorso dell'index.json dell'utente (default_key_id, flag, ecc.)."""
    return os.path.join(_user_dir(username), "index.json")

def _key_path(username: str, key_id: str) -> str:
    """Percorso del file JSON che contiene i metadati della specifica chiave."""
    return os.path.join(_user_dir(username), f"{key_id}.json")

def _ensure_user_dir(username: str) -> None:
    """Crea la cartella dell'utente se non esiste (per organizzare i file per-utente)."""
    os.makedirs(_user_dir(username), exist_ok=True)

def _save_json_atomic(path: str, obj: Dict[str, Any]) -> None:
    """
    Salva un JSON in modo ATOMICO:
    - scrive su <path>.tmp,
    - flush + fsync (garantisce che i dati finiscano su disco),
    - os.replace(tmp, path) (sostituzione atomica: o tutto o niente).
    """
    tmp = path + ".tmp"                                   # nome temporaneo per scrittura sicura
    os.makedirs(os.path.dirname(path), exist_ok=True)     # assicura che la cartella esista
    with open(tmp, "w", encoding="utf-8") as f:           # apre il file temporaneo in scrittura testo
        json.dump(obj, f, indent=2, sort_keys=True)       # scrive l'oggetto JSON (ordinato e leggibile)
        f.flush()                                         # svuota il buffer Python
        os.fsync(f.fileno())                              # forza la scrittura su disco (evita file troncati)
    os.replace(tmp, path)                                  # rimpiazza in modo atomico il file finale

def _load_json_or_empty(path: str) -> Dict[str, Any]:
    """Carica un JSON se esiste, altrimenti restituisce un dict vuoto."""
    if not os.path.exists(path):                          # se il file non c'è
        return {}                                         # torna un dict vuoto
    with open(path, "r", encoding="utf-8") as f:          # altrimenti apri in lettura
        return json.load(f)                               # e parse JSON





def _load_master_key(path: str = DEFAULT_KEY_PATH) -> bytes:
    """
    Legge la master key da `secrets/master.key` (Base64) e ritorna i 32 byte.
    Non crea nulla: il file deve già esistere.
    """
    key = load_master_key("QuEST4_P4ssW0rD_e_S1CuR4_")

    return key


def _list_key_files(user: str):
    """Ritorna i file .json delle chiavi (esclude index.json). Deve essercene al massimo 1."""
    ud = _user_dir(user)
    if not os.path.isdir(ud):
        return []
    return [f for f in os.listdir(ud) if f.endswith(".json") and f != "index.json"]

# ====== FUNZIONE PRINCIPALE: CreateKeys (UNA SOLA COPPIA PER UTENTE, IDEMPOTENTE) ======
def CreateKeys(username: str) -> Dict[str, Any]:
    """
    Crea una (sola) coppia di chiavi Ed25519 per l'utente (se non esiste già).
    Requisiti rispettati:
      - UNA SOLA coppia per utente: se esiste, NON ricrea (idempotenza) e restituisce la stessa.
      - Privata serializzata in Raw (32B) e CIFRATA A RIPOSO con AES-GCM (master key da env).
      - Salvataggio ATOMICO su JSON in keystore/<user>/.
      - key_id = ed25519-YYYYMMDD-<shorthex>.
    Ritorna metadati utili al client: { key_id, algo, public_key_b64, created_at }.
    """

    _ensure_user_dir(username)                            # assicura che esista la cartella keystore/<username>/
    idx_path = _index_path(username)                      # calcola il path dell'index.json dell'utente
    idx = _load_json_or_empty(idx_path)                   # carica l'indice (potrebbe essere vuoto se prima volta)

    # ---- IDEMPOTENZA: se esiste già una chiave attiva per l'utente, NON ricreare ----
    existing_key_id = idx.get("default_key_id")           # legge la chiave di default (se impostata)
    if existing_key_id:                                   # se è presente un default_key_id
        existing_path = _key_path(username, existing_key_id)  # path del file JSON della chiave esistente
        rec = _load_json_or_empty(existing_path)          # prova a caricare quel record
        if rec and rec.get("status") == "active":         # se il record esiste ed è attivo
            logging.info("[CreateKeys] Esiste già una chiave attiva per user=%s, key_id=%s", username, existing_key_id)
            # ritorna i metadati della chiave ESISTENTE (idempotenza)
            return {
                "key_id": existing_key_id,               # restituisce lo stesso key_id già in uso
                "algo": rec.get("algo", "ed25519"),      # algoritmo (ed25519)
                "public_key_b64": rec["public_key_b64"], # pubblica in base64 (consultabile in futuro)
                "created_at": rec.get("created_at", "")  # timestamp di creazione (se presente)
            }

    # ---- ALTRIMENTI: genera una nuova coppia Ed25519 per l'utente ----
    sk = ed25519.Ed25519PrivateKey.generate()             # genera la chiave privata Ed25519 (nuova)
    pk = sk.public_key()                                  # deriva la chiave pubblica corrispondente

    # Serializza la privata in formato RAW (32B) SENZA cifratura (NoEncryption) perché la cifriamo noi con AES-GCM
    priv_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,              # formato "Raw" (byte nudi) come da specifiche
        format=serialization.PrivateFormat.Raw,           # private key in rappresentazione Raw (32B per Ed25519)
        encryption_algorithm=serialization.NoEncryption() # nessuna cifratura qui: la faremo a mano con master key
    )

    # Serializza la pubblica in formato RAW (32B) per salvarla in JSON (in chiaro) come base64
    pub_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,              # formato "Raw" (byte nudi)
        format=serialization.PublicFormat.Raw             # public key Raw (32B per Ed25519)
    )

    # Prepara il cifratore AES-GCM con la master key caricata dall'env (richiesta "cifratura a riposo")
    aesgcm = AESGCM(_load_master_key())                   # inizializza AEAD con la master key di 32 byte

    # Genera il NONCE (IV) da 12 byte per AES-GCM "a riposo" (unico per questa cifratura della privata)
    nonce_at_rest = secrets.token_bytes(12)               # 12B random: requisito di unicità per sicurezza GCM

    # Cifra la privata Raw: risultato include internamente il tag di autenticazione (AEAD)
    enc_priv = aesgcm.encrypt(nonce_at_rest, priv_raw, None)  # AAD=None: non serve associare dati extra al blob su disco

    # Crea un identificatore leggibile e univoco per la chiave: ed25519-YYYYMMDD-<shorthex>
    key_id = f"ed25519-{time.strftime('%Y%m%d')}-{secrets.token_hex(2)}"  # es. "ed25519-20250825-1a2b"

    # Prepara il record JSON della chiave con metadati, pubblica in chiaro e privata cifrata
    rec = {
        "key_id": key_id,                                 # identificatore della chiave (leggibile + univoco)
        "username": username,                             # a chi appartiene la chiave (scoping per-utente)
        "algo": "ed25519",                                # algoritmo usato
        "public_key_b64": b64e(pub_raw),                 # chiave pubblica (32B) in base64 (consultabile in futuro)
        "enc_priv_key_b64": b64e(enc_priv),              # privata cifrata con AES-GCM (base64 su JSON)
        "nonce_b64": b64e(nonce_at_rest),                # nonce (12B) usato per cifrare la privata (serve a decifrare)
        "created_at": _now_iso(),                         # timestamp ISO di creazione (UTC)
        "status": "active"                                # stato attuale (active | deleted)
    }

    # Salva il record della chiave su file JSON in modo ATOMICO (evita file corrotti su crash)
    _save_json_atomic(_key_path(username, key_id), rec)   # scrittura atomica del file "keystore/<user>/<key_id>.json"

    # Aggiorna (o crea) l'index.json dell'utente impostando la chiave di default se non presente
    if not idx.get("default_key_id"):                     # se non c'era una chiave di default
        idx["default_key_id"] = key_id                    # imposta questa come default (una sola coppia per utente)
    if "registration_locked" not in idx:                  # coerente con i requisiti Fase 4 (vincolo offline)
        idx["registration_locked"] = False                # per default, utente abilitato a creare (non bloccato)
    _save_json_atomic(idx_path, idx)                      # salva l'index aggiornato in modo atomico

    # Log informativo (senza mai esporre materiale sensibile come priv_raw o master key)
    logging.info("[CreateKeys] Creata nuova chiave: user=%s key_id=%s", username, key_id)

    # Ritorna al chiamante i metadati necessari (pubblica consultabile + info di creazione)
    return {
        "key_id": key_id,                                 # ID della chiave appena creata
        "algo": "ed25519",                                # algoritmo (coerente con il resto del progetto)
        "public_key_b64": rec["public_key_b64"],          # pubblica in base64 (usata da GetPublicKey / client)
        "created_at": rec["created_at"]                   # data/ora di creazione (per audit/rotazione)
    }


def GetPublicKey(target_user: str, key_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Restituisce la chiave pubblica di 'target_user'.
    - Poiché ogni utente ha UNA SOLA coppia, 'key_id' è opzionale.
    - Se 'key_id' è passato, deve coincidere con l’unica chiave presente; altrimenti errore.
    Ritorna: { "key_id", "algo", "public_key_b64" }.
    """
    # Trova l’unico file-chiave dell’utente
    key_files = _list_key_files(target_user)
    if len(key_files) == 0:
        logging.info("[GetPublicKey] Nessuna chiave per user=%s", target_user)
        raise FileNotFoundError("KeyNotFound")

    # Carica il record
    path = os.path.join(_user_dir(target_user), key_files[0])
    with open(path, "r", encoding="utf-8") as f:
        rec = json.load(f)

    # Verifica stato e (eventuale) corrispondenza key_id
    if rec.get("status") != "active":
        raise FileNotFoundError("KeyNotFound")

    actual_id = rec.get("key_id")
    if key_id is not None and key_id != actual_id:
        # è stata chiesta una key_id diversa da quella unica disponibile
        raise FileNotFoundError("KeyNotFound")

    # Risposta minimale e coerente
    out = {
        "key_id": actual_id,
        "algo": rec.get("algo", "ed25519"),
        "public_key_b64": rec["public_key_b64"],
    }
    logging.info("[GetPublicKey] OK: user=%s, key_id=%s, public_key_b64=%s", target_user, actual_id, out["public_key_b64"])
    return out



def DeleteKeys(auth_user: str) -> Dict[str, Any]: #NOTA BENE che deve essere l'utente autenticato
    """
    Elimina la chiave dell'utente. Solo il proprietario può cancellare.
    - auth_user: utente autenticato (proprietario).
    - target_user: opzionale; se fornito deve coincidere con auth_user.
    Azioni:
      * rimuove il file JSON della chiave (distruzione effettiva),
      * in index.json mette: default_key_id = None, registration_locked = true.
    Ritorna: { "deleted": [key_id] }
    """
    target = auth_user
    # Trova l'unico file-chiave 
    key_files = _list_key_files(target)
    if len(key_files) == 0:
        logging.info("[DeleteKeys] Nessuna chiave da cancellare: user=%s", target)
        raise FileNotFoundError("KeyNotFound")


    # Carica il record per ottenere il key_id e poi elimina fisicamente il file
    path = os.path.join(_user_dir(target), key_files[0])
    rec = _load_json_or_empty(path)

    key_id = rec.get("key_id")
    try:
        os.remove(path)  # cancellazione effettiva del file della chiave
    except OSError as e:
        logging.error("[DeleteKeys] Impossibile rimuovere %s: %s", path, e)
        raise

    # Aggiorna index.json: default_key_id=None, registration_locked=True
    idx_path = _index_path(target)
    idx = _load_json_or_empty(idx_path)
    idx["default_key_id"] = None
    idx["registration_locked"] = True  # vincolo: nuova registrazione solo offline
    _save_json_atomic(idx_path, idx)

    logging.info("[DeleteKeys] OK: user=%s key_id=%s (registration_locked=true)", target, key_id)
    return {"deleted": [key_id]}

def SignDoc(auth_user: str, doc_path: str) -> Dict[str, Any]:
    """
    Firma SHA-256(doc) con la chiave privata dell'utente 'auth_user'.
    - Precondizione: utente autenticato, e ha UNA SOLA chiave attiva nel keystore.
    - Output: crea <doc_path>.sig (firma base64) e ritorna metadati.
    """
    # 1) Verifiche di base
    if not os.path.isfile(doc_path):
        raise FileNotFoundError(f"Documento non trovato: {doc_path}")

    # 2) Trova l’unico file-chiave dell’utente
    key_files = _list_key_files(auth_user)
    if len(key_files) == 0:
        raise FileNotFoundError("KeyNotFound")

    key_rec_path = os.path.join(_user_dir(auth_user), key_files[0])
    rec = _load_json_or_empty(key_rec_path)

    # 3) Decifra la privata a riposo con la master key (AES-GCM)
    mk = _load_master_key()
    aes = AESGCM(mk)
    nonce_b64 = rec["nonce_b64"]
    enc_b64 = rec["enc_priv_key_b64"]
    priv_raw = aes.decrypt(base64.b64decode(nonce_b64),
                           base64.b64decode(enc_b64),
                           None)

    # 4) Ricostruisci la privata Ed25519
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(priv_raw)

    # 5) Calcola hash del documento (SHA-256)
    h = hashlib.sha256()
    with open(doc_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    doc_hash = h.digest()  # 32 byte
    doc_hash_b64 = base64.b64encode(doc_hash).decode()

    '''
    doc_hash = il vero hash in forma binaria (32 byte).
    doc_hash_b64 = la rappresentazione testuale di quegli stessi 32 byte, ottenuta con Base64, per poterlo inserire in file JSON o stamparlo.
    '''

    # 6) Firma l’hash (Ed25519 firma direttamente 32B)
    signature = sk.sign(doc_hash)
    signature_b64 = base64.b64encode(signature).decode()
    '''
    signature = firma Ed25519 in binario (64 byte).
    signature_b64 = la stessa firma codificata in base64 (stringa leggibile, utile per JSON o trasmissione).
    '''

    # 7) Scrivi firma “detached” accanto al file: <doc>.sig
    sig_path = doc_path + ".sig"
    with open(sig_path, "w", encoding="utf-8") as f:
        # formato semplice e leggibile; puoi anche usare solo la firma base64 se preferisci
        json.dump({
            "username": auth_user, #chi ha firmato 
            "key_id": rec.get("key_id"), #chiave di chi ha firmato 
            "algo": rec.get("algo", "ed25519"),
            "hash_alg": "sha256",
            "doc_hash_b64": doc_hash_b64,
            "signature_b64": signature_b64
        }, f, indent=2, sort_keys=True)

    logging.info("[SignDoc] OK: user=%s key_id=%s doc=%s sig=%s",
                 auth_user, rec.get("key_id"), doc_path, sig_path)

    return {
        "username": auth_user,
        "key_id": rec.get("key_id"),
        "algo": rec.get("algo", "ed25519"),
        "hash_alg": "sha256",
        "doc_hash_b64": doc_hash_b64,
        "signature_b64": signature_b64,
        "signature_path": sig_path
    }