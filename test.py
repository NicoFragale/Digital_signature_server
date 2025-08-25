# test.py
import os
import base64
import logging
from typing import Dict, Any, Optional 
# importa la CreateKeys che hai messo in OpSec.py
from OpSec import CreateKeys, KEYSTORE_DIR, GetPublicKey, DeleteKeys, SignDoc
from Masterkey import init_master_key

def _ensure_master_key():
    """
    Se DSS_MASTER_KEY non è impostata, la genera al volo (solo per test).
    In produzione impostala tu nell'ambiente.
    """
    if "DSS_MASTER_KEY" not in os.environ:
        os.environ["DSS_MASTER_KEY"] = base64.b64encode(os.urandom(32)).decode()

def testCreateKeys(user):

    _ensure_master_key()           # garantisce che la master key esista (per il test)
    username = user        

    res = CreateKeys(username)     # crea (o riusa) la coppia di chiavi per l'utente
    logging.info(f"[TEST] CreateKeys result: %s", res)

    user_dir = os.path.join(KEYSTORE_DIR, username)
    logging.info("[TEST] Keystore path: %s", user_dir)

def testGetKey(username: str, key_id: Optional[str]):

    try:
        GetPublicKey(username, key_id)
    except FileNotFoundError as e:
        logging.error("[TEST] GetPublicKey error for user='%s' key_id='%s': %s",
                      username, key_id, e)

def testSign():

    user = input("Utente che firma: ").strip()
    doc = input("Percorso documento da firmare: ").strip()

    res = SignDoc(auth_user=user, doc_path=doc)
    print("[TEST] Firma OK")
    print(" - key_id:", res["key_id"])
    print(" - signature_path:", res["signature_path"])


if __name__ == "__main__":
    
    choice = input("Esegui testCreateKeys(), testGetKey(), testDeleteKey() o testSignDoc()? (c/g/d/s): ").strip().lower()

    if choice == "g":
        user = input("Inserisci username: ").strip()
        kid = input("Inserisci key_id (vuoto per default): ").strip()
        kid = None if kid == "" else kid
        testGetKey(user, kid)

    elif choice == "d":
        user = input("Inserisci username da eliminare: ").strip()
        try:
            res = DeleteKeys(auth_user=user)
            print(f"[TEST] DeleteKeys OK: {res}")
        except Exception as e:
            print(f"[TEST] DeleteKeys error: {e}")

    elif choice == "c":
        user = input("Inserisci username: ").strip()
        testCreateKeys(user)

    elif choice == "s":
        testSign()

