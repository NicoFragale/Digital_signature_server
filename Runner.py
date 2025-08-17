from server import DigitalSignatureSocketServer
from client import Client  

if __name__ == "__main__":
    server = DigitalSignatureSocketServer()
    server.start()