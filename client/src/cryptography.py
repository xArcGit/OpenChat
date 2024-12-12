import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class RSAEncryptorDecryptor:
    def __init__(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey):
        """
        Initialize the RSAEncryptorDecryptor with private and public keys.

        Args:
          private_key (rsa.RSAPrivateKey): The private key for decryption.
          public_key (rsa.RSAPublicKey): The public key for encryption.
        """
        self.private_key = private_key
        self.public_key = public_key

    def encrypt_message(self, message: str) -> str:
        """
        Encrypt a message using the public key.

        Args:
          message (str): The message to encrypt.

        Returns:
          str: The Base64 encoded encrypted message.
        """
        encrypted_message = self.public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(encrypted_message).decode("utf-8")

    def decrypt_message(self, encrypted_message: str) -> str:
        """
        Decrypt a message using the private key.

        Args:
          encrypted_message (str): The Base64 encoded encrypted message.

        Returns:
          str: The decrypted message.
        """
        encrypted_message_bytes = base64.b64decode(encrypted_message)
        decrypted_message = self.private_key.decrypt(
            encrypted_message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_message.decode("utf-8")
