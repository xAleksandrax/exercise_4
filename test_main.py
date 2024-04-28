import pytest
from fastapi.testclient import TestClient
from main import app, SymmetricKey, Message
import base64

client = TestClient(app)

def test_get_symmetric_key():
    """
    Test to retrieve a symmetric key.

    Asserts:
        - The status code is 200.
        - Response content contains "Generated Symmetric Key".
    """
    response = client.get("/symmetric/key")
    assert response.status_code == 200
    assert "Generated Symmetric Key" in response.content.decode()

def test_set_symmetric_key():
    """
    Test to set a symmetric key.

    Asserts:
        - The status code is 200.
        - The response JSON matches the expected message.
    """
    response = client.post("/symmetric/key", json={"key": "test_key"})
    assert response.status_code == 200
    assert response.json() == {"message": "Symmetric key set successfully"}

def test_encode_without_key():
    """
    Test encoding without providing a key.

    Asserts:
        - The status code is 422 (Unprocessable Entity).
    """
    response = client.post("/symmetric/encode", json={"message": "test_message"})
    assert response.status_code == 422

def test_decode_without_key():
    """
    Test decoding without providing a key.

    Asserts:
        - The status code is 422 (Unprocessable Entity).
    """
    response = client.post("/symmetric/decode", json={"encrypted_message": "test_encrypted_message"})
    assert response.status_code == 422

def test_get_asymmetric_keys():
    """
    Test to retrieve asymmetric keys.

    Asserts:
        - The status code is 200.
        - Response content contains "Private Key" and "Public Key".
    """
    response = client.get("/asymmetric/key")
    assert response.status_code == 200
    assert "Private Key" in response.content.decode()
    assert "Public Key" in response.content.decode()

def test_set_asymmetric_keys():
    """
    Test to set asymmetric keys.

    Asserts:
        - The status code is 200.
        - The response JSON matches the expected message.
    """
    response = client.post("/asymmetric/key", json={"private_key": "test_private_key", "public_key": "test_public_key"})
    assert response.status_code == 200
    assert response.json() == {"message": "Asymmetric keys set successfully"}

if __name__ == "__main__":
    pytest.main()
