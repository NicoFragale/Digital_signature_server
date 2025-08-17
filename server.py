import socket
import ssl

class DigitalSignatureSocketServer:
    """
    Digital Signature Server (DSS) con socket e SSL.
    Classe di base per la gestione delle connessioni sicure.
    """

    def __init__(self, host='localhost', port=5000, certfile="tls/server-cert.pem", keyfile="tls/server-key.pem"):
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
        # Configura SSL
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        self.server_socket = ssl_context.wrap_socket(self.server_socket, server_side=True)

    def handle_client(self, client_socket):
        try:
            data = client_socket.recv(1024)
            if data:
                print(f"Dati ricevuti: {data.decode('utf-8')}")
                client_socket.sendall(b"Messaggio ricevuto dal server")
        except Exception as e:
            print(f"Errore: {e}")
        finally:
            client_socket.close()

    def start(self):
        print(f"Server in ascolto su {self.host}:{self.port}")
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connessione accettata da {client_address}")
                self.handle_client(client_socket)
        except KeyboardInterrupt:
            print("Interruzione manuale del server")
        finally:
            self.shutdown_server()

    def shutdown_server(self):
        self.server_socket.close()
        print("Server chiuso")