# MasterKey.py
import os, base64, stat

DEFAULT_KEY_PATH = os.path.join("secrets", "master.key")

def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)

def _write_key_file(path: str, raw32: bytes):
    # scrivi con permessi 600 (solo owner)
    _ensure_dir(path)
    # su Unix: usa os.open per impostare i permessi all’atto della creazione
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(base64.b64encode(raw32))
            f.write(b"\n")
    except FileExistsError:
        # se il file appare tra open e write, lo tratteremo come "già esistente" altrove
        raise

def _read_key_file(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read().strip()
    try:
        key = base64.b64decode(data)
    except Exception as e:
        raise RuntimeError(f"Master key non è base64 valido in {path}") from e
    if len(key) != 32:
        raise RuntimeError(f"Master key in {path} non è lunga 32 byte")
    return key

def init_master_key(path: str = DEFAULT_KEY_PATH, export_env: bool = True) -> bytes:
    """
    Inizializza/recupera la master key persistente.
    - Se il file non esiste: genera 32B, salva base64, permessi 600.
    - Se esiste: legge e valida (32B).
    - Se export_env=True: imposta os.environ['DSS_MASTER_KEY'] = base64(key).
    Ritorna i 32 byte grezzi.
    """
    if not os.path.exists(path):
        raw = os.urandom(32)
        _write_key_file(path, raw)
    else:
        # opzionalmente stringi i permessi se sono troppo permissivi
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass  # su Windows ignorabile

    key = _read_key_file(path)

    if export_env:
        os.environ["DSS_MASTER_KEY"] = base64.b64encode(key).decode()

    return key

def show_master_key_b64(path: str = DEFAULT_KEY_PATH) -> str:
    """Ritorna la master key in base64 (utile per debug/diagnostica)."""
    return base64.b64encode(init_master_key(path, export_env=False)).decode()


if __name__ == "__main__":
    print(show_master_key_b64())