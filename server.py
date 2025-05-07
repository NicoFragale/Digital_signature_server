import socket
import ssl

class DigitalSignatureSocketServer:
    """
    Digital Signature Server (DSS) con socket e SSL.
    Classe di base per la gestione delle connessioni sicure.
    """

    def __init__(self, host='0.0.0.0', port=5000, certfile='server-cert.pem', keyfile='server-key.pem'):
        """
        Inizializza il server con socket e SSL.
        
        Args:
            host (str): Indirizzo IP su cui il server ascolta.
            port (int): Porta su cui il server ascolta.
            certfile (str): Il certificato SSL per il server.
            keyfile (str): La chiave privata SSL per il server.
        """
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        # Crea il socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)