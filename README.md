# Secure Messaging API
This repository contains the source code for a Secure Messaging API built with FastAPI in Python. The API provides endpoints for symmetric and asymmetric encryption and decryption, as well as message signing and verification.

# Features
Generate and retrieve symmetric keys
Generate and retrieve asymmetric key pairs
Encrypt and decrypt messages using symmetric keys
Sign and verify messages using asymmetric keys

# Usage
Run the FastAPI server:
bash
Copy code
uvicorn main:app --reload
Open your web browser and go to http://127.0.0.1:8000 to access the API documentation.
Use the provided endpoints to perform symmetric and asymmetric encryption/decryption, and message signing/verification.

# Endpoints
Symmetric Key
GET /symmetric/key: Generate and retrieve a symmetric key.
POST /symmetric/key: Set a symmetric key.
POST /symmetric/encode: Encrypt a message using a symmetric key.
POST /symmetric/decode: Decrypt a message using a symmetric key.
Asymmetric Key
GET /asymmetric/key: Generate and retrieve asymmetric keys.
GET /asymmetric/key/ssh: Retrieve asymmetric keys in OpenSSH format.
POST /asymmetric/key: Set asymmetric keys.
POST /asymmetric/encode: Encrypt a message using an asymmetric public key.
POST /asymmetric/decode: Decrypt a message using an asymmetric private key.
POST /asymmetric/sign: Sign a message using an asymmetric private key.
POST /asymmetric/verify: Verify a message using an asymmetric signature.

# Contributing
Contributions are welcome! Feel free to open issues or pull requests for any improvements or bug fixes.
