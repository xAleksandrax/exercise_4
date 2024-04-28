from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from typing import Optional, Dict
from pydantic import BaseModel
import base64
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

symmetric_key = None
asymmetric_private_key = None
asymmetric_public_key = None

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """
    Root route to render the index.html template.

    Args:
        request (Request): The incoming request object.

    Returns:
        TemplateResponse: HTML template response.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/symmetric/key", response_class=HTMLResponse)
async def get_symmetric_key(request: Request):
    """
    Endpoint to generate and retrieve a symmetric key.

    Args:
        request (Request): The incoming request object.

    Returns:
        TemplateResponse: HTML template response containing the generated symmetric key.
    """
    global symmetric_key
    symmetric_key = generate_symmetric_key()
    return templates.TemplateResponse("symmetric_key.html", {"request": request, "key": symmetric_key})

@app.get("/asymmetric/key", response_class=HTMLResponse)
async def get_asymmetric_keys(request: Request):
    """
    Endpoint to generate and retrieve asymmetric keys.

    Args:
        request (Request): The incoming request object.

    Returns:
        TemplateResponse: HTML template response containing the generated asymmetric keys.
    """
    global asymmetric_private_key, asymmetric_public_key
    asymmetric_private_key, asymmetric_public_key = generate_asymmetric_keys()
    return templates.TemplateResponse("asymmetric_key.html", {"request": request, "private_key": asymmetric_private_key, "public_key": asymmetric_public_key})

class SymmetricKey(BaseModel):
    key: str

class Message(BaseModel):
    message: str
    encrypted_message: str

def generate_symmetric_key():
    """
    Generate a symmetric encryption key.

    Returns:
        str: The generated symmetric key.
    """
    return Fernet.generate_key().decode()

def generate_asymmetric_keys():
    """
    Generate asymmetric (public and private) key pair.

    Returns:
        Tuple[str, str]: The private and public keys in PEM and OpenSSH formats respectively.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8'),
        public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
    )

def encode_message(message: str, key: str):
    """
    Encrypt a message using a symmetric key.

    Args:
        message (str): The message to be encrypted.
        key (str): The symmetric encryption key.

    Returns:
        str: The encrypted message.
    """
    cipher = Fernet(key.encode())
    return cipher.encrypt(message.encode()).decode()

def decode_message(encrypted_message: str, key: str):
    """
    Decrypt a message using a symmetric key.

    Args:
        encrypted_message (str): The encrypted message.
        key (str): The symmetric encryption key.

    Returns:
        str: The decrypted message.
    """
    cipher = Fernet(key.encode())
    try:
        return cipher.decrypt(encrypted_message.encode()).decode()
    except InvalidToken:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

def sign_message(message: str, private_key: str):
    """
    Sign a message using an asymmetric private key.

    Args:
        message (str): The message to be signed.
        private_key (str): The private key in PEM format.

    Returns:
        str: The hexadecimal signature of the message.
    """
    private_key = serialization.load_pem_private_key(
        private_key.encode(),
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

def verify_message(message: str, signature: str, public_key: str):
    """
    Verify the authenticity of a message using an asymmetric public key.

    Args:
        message (str): The message to be verified.
        signature (str): The hexadecimal signature of the message.
        public_key (str): The public key in OpenSSH format.

    Returns:
        bool: True if the message is verified, False otherwise.
    """
    public_key = serialization.load_ssh_public_key(
        public_key.encode(),
        backend=default_backend()
    )
    try:
        public_key.verify(
            bytes.fromhex(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

@app.get("/symmetric/key")
def get_symmetric_key():
    """
    Endpoint to generate and retrieve a symmetric key.

    Returns:
        Dict[str, str]: A dictionary containing the generated symmetric key.
    """
    global symmetric_key
    symmetric_key = generate_symmetric_key()
    return {"key": symmetric_key}

@app.post("/symmetric/key")
def set_symmetric_key(key: SymmetricKey):
    """
    Endpoint to set a symmetric key.

    Args:
        key (SymmetricKey): The symmetric key to be set.

    Returns:
        Dict[str, str]: A message confirming the symmetric key has been set.
    """
    global symmetric_key
    symmetric_key = key.key
    return {"message": "Symmetric key set successfully"}

@app.post("/symmetric/encode")
def encode_symmetric_message(message: Message):
    """
    Endpoint to encrypt a message using a symmetric key.

    Args:
        message (Message): The message to be encrypted.

    Returns:
        Dict[str, str]: A dictionary containing the encrypted message.
    """
    global symmetric_key
    if not symmetric_key:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    return {"encrypted_message": encode_message(message.message, symmetric_key)}

@app.post("/symmetric/decode")
def decode_symmetric_message(encrypted_message: Message):
    """
    Endpoint to decrypt a message using a symmetric key.

    Args:
        encrypted_message (Message): The encrypted message.

    Returns:
        Dict[str, str]: A dictionary containing the decrypted message.
    """
    global symmetric_key
    if not symmetric_key:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    return {"decrypted_message": decode_message(encrypted_message.encrypted_message, symmetric_key)}

@app.get("/asymmetric/key")
def get_asymmetric_keys():
    """
    Endpoint to generate and retrieve asymmetric keys.

    Returns:
        Dict[str, str]: A dictionary containing the generated asymmetric keys.
    """
    global asymmetric_private_key, asymmetric_public_key
    asymmetric_private_key, asymmetric_public_key = generate_asymmetric_keys()
    return {"private_key": asymmetric_private_key, "public_key": asymmetric_public_key}

@app.get("/asymmetric/key/ssh")
def get_asymmetric_ssh_keys():
    """
    Endpoint to retrieve asymmetric keys in OpenSSH format.

    Returns:
        Dict[str, str]: A dictionary containing the asymmetric keys in OpenSSH format.
    """
    if not asymmetric_private_key or not asymmetric_public_key:
        raise HTTPException(status_code=400, detail="Asymmetric keys not generated")
    return {"private_key": asymmetric_private_key, "public_key": asymmetric_public_key}

@app.post("/asymmetric/key")
def set_asymmetric_keys(keys: Dict[str, str] = Body(...)):
    """
    Endpoint to set asymmetric keys.

    Args:
        keys (Dict[str, str]): A dictionary containing the private and public keys.

    Returns:
        Dict[str, str]: A message confirming the asymmetric keys have been set.
    """
    global asymmetric_private_key, asymmetric_public_key
    asymmetric_private_key = keys.get("private_key")
    asymmetric_public_key = keys.get("public_key")
    return {"message": "Asymmetric keys set successfully"}

@app.post("/asymmetric/verify")
def verify_asymmetric_message(message: str = Body(...), signature: str = Body(...)):
    """
    Endpoint to verify a message using an asymmetric signature.

    Args:
        message (str): The message to be verified.
        signature (str): The signature of the message.

    Returns:
        Dict[str, bool]: A dictionary containing the verification result.
    """
    if not asymmetric_private_key:
        raise HTTPException(status_code=400, detail="Asymmetric private key not set")
    if not asymmetric_public_key:
        raise HTTPException(status_code=400, detail="Asymmetric public key not set")
    return {"verified": verify_message(message, signature, asymmetric_public_key)}

@app.post("/asymmetric/sign")
def sign_asymmetric_message(message: str = Body(...)):
    """
    Endpoint to sign a message using an asymmetric private key.

    Args:
        message (str): The message to be signed.

    Returns:
        Dict[str, str]: A dictionary containing the hexadecimal signature of the message.
    """
    if not asymmetric_private_key:
        raise HTTPException(status_code=400, detail="Asymmetric private key not set")
    return {"signature": sign_message(message, asymmetric_private_key)}

@app.post("/asymmetric/encode")
def encode_asymmetric_message(message: str = Body(...)):
    """
    Endpoint to encrypt a message using an asymmetric public key.

    Args:
        message (str): The message to be encrypted.

    Returns:
        Dict[str, str]: A dictionary containing the encrypted message.
    """
    if not asymmetric_public_key:
        raise HTTPException(status_code=400, detail="Asymmetric public key not set")
    return {"encrypted_message": encode_message(message, asymmetric_public_key)}

@app.post("/asymmetric/decode")
def decode_asymmetric_message(encrypted_message: str = Body(...)):
    """
    Endpoint to decrypt a message using an asymmetric private key.

    Args:
        encrypted_message (str): The encrypted message.

    Returns:
        Dict[str, str]: A dictionary containing the decrypted message.
    """
    if not asymmetric_private_key:
        raise HTTPException(status_code=400, detail="Asymmetric private key not set")
    return {"decrypted_message": decode_message(encrypted_message, asymmetric_private_key)}
