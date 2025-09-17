# Digital Signature Service (DSS)

This project implements a **Digital Signature Server (DSS)** that acts as a trusted third party:  
- generates and manages key pairs for users,  
- stores private keys in encrypted form,  
- provides digital signatures upon user request.  

The system is composed of a **server** and a **client**, which communicate through a secure channel based on modern cryptography (Diffie–Hellman, HKDF, AES-GCM).

---

## 📖 Main Features

- **Key creation (CreateKeys)** → generates and stores an Ed25519 key pair for the user.  
- **Document signing (SignDoc)** → computes the digital signature of the SHA-256 digest of a file.  
- **Retrieve public keys (GetPublicKey)** → returns the public key of a user.  
- **Delete keys (DeleteKeys)** → permanently deletes the user’s key pair.  

All operations are only available after:  
1. Handshake with Perfect Forward Secrecy (X25519 + HKDF-SHA256).  
2. Activation of an authenticated and encrypted channel with **AES-256-GCM**.  
3. User authentication (username + password, with mandatory password change at first login).  

---

## 🏗️ Architecture

- **Server (`server.py`)**  
  - Listens for new TCP connections.  
  - Establishes the secure channel.  
  - Authenticates users.  
  - Manages the encrypted keystore and cryptographic operations.  

- **Client (`client.py`)**  
  - Connects to the server.  
  - Negotiates the secure channel and authenticates the user.  
  - Allows the user to invoke operations via a command-line interface.  

---

## ⚙️ Requirements

- Python **3.10+**
- Required libraries (installable with `pip install -r requirements.txt`):
  - `cryptography`
  - `socket`
  - `json`
  - `base64`
  - `hashlib`

---

## 🚀 Execution

### 1. Start the server

python3 server.py

### 2. Start the client

python3 client.py

---

## 🧠 Authors

- **[Range](https://github.com/NicoFragale)**
- **[Ex0DiUs](https://github.com/Ed3f)**

## 📚 Academic Info

**Course:** Foundations of Cybersecurity
**Program:** Master's Degree in Cybersecurity, University of Pisa  
**Academic Year:** 2024/2025

## 📜 License

This project is intended for academic purposes. Please contact the authors for reuse or modification permissions.