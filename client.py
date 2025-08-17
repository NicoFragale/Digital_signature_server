import socket
import ssl

class Client:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port

    def start(self):
        #context = ssl.create_default_context()
        context = ssl._create_unverified_context()
        print(f"Connessione al server {self.host}:{self.port}")
        with socket.create_connection((self.host, self.port)) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                ssock.sendall(b"Messaggio inviato dal client")
                data = ssock.recv(1024)
                print(f"Dati ricevuti: {data.decode('utf-8')}")

if __name__ == "__main__":
    client = Client()
    client.start()