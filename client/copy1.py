import aiohttp
from typing import Optional, List, Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import asyncio
import sys
import os
import base64
import websockets
import json
import curses
import yaml

SERVER_URI = "http://localhost:3000"
WEBSOCKET_URI = "ws://localhost:3000"


class RSAKeyManager:
    def __init__(self, username: Optional[str] = None):
        """
        Manage RSA keys for a user, saving and loading them from disk.

        Args:
            username (str): The username for key management.
        """
        self.username = username
        self.key_dir = "keys"
        os.makedirs(self.key_dir, exist_ok=True)
        self.private_key: Optional[rsa.RSAPrivateKey] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None

    def generate_keys(self) -> None:
        """
        Generate and store RSA public/private key pair.
        """
        if not self.username:
            raise ValueError("Username must be set before generating keys.")

        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        self.save_keys()

    def save_keys(self) -> None:
        """
        Save the generated RSA keys to a YAML file as base64 encoded strings.
        """
        if not self.private_key or not self.public_key:
            raise ValueError("Keys have not been generated yet.")

        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_key_base64 = base64.b64encode(private_pem).decode("utf-8")
        public_key_base64 = base64.b64encode(public_pem).decode("utf-8")

        key_data = {
            "username": self.username,
            "private_key": private_key_base64,
            "public_key": public_key_base64,
        }

        try:
            with open(f"{self.key_dir}/conf.yml", "w") as f:
                yaml.dump(key_data, f)
        except Exception as e:
            print(f"Error saving keys: {e}")

    def load_keys(self) -> None:
        """
        Load RSA keys and username from the YAML file.
        """
        try:
            with open(f"{self.key_dir}/conf.yml", "r") as f:
                key_data = yaml.safe_load(f)

            if not key_data:
                raise ValueError("No key data found in the YAML file.")

            if (
                "private_key" not in key_data
                or "public_key" not in key_data
                or "username" not in key_data
            ):
                raise ValueError("Missing key data in the YAML file.")

            private_key_base64 = key_data["private_key"]
            public_key_base64 = key_data["public_key"]
            self.username = key_data["username"]

            private_pem = base64.b64decode(private_key_base64)
            public_pem = base64.b64decode(public_key_base64)

            self.private_key = serialization.load_pem_private_key(
                private_pem, password=None, backend=default_backend()
            )

            self.public_key = serialization.load_pem_public_key(
                public_pem, backend=default_backend()
            )

        except Exception as e:
            print(f"Error loading keys from YAML: {e}")

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key

    def get_username(self):
        return self.username


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


class MessageClient:
    def __init__(self):
        """
        MessageClient manages communication with a remote message server.
        """
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """
        Enter async context manager to start a session.
        """
        await self.start_session()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """
        Exit async context manager and close the session.
        """
        await self.close_session()

    async def start_session(self):
        """
        Start a persistent aiohttp session.
        """
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)  # 5-second timeout
            )

    async def close_session(self):
        """
        Close the aiohttp session.
        """
        if self.session:
            await self.session.close()
            self.session = None

    async def _handle_response(
        self, response: aiohttp.ClientResponse
    ) -> Optional[Dict[str, Any]]:
        """
        Handle the response from an HTTP request.

        Args:
            response (aiohttp.ClientResponse): The response object.

        Returns:
            Optional[Dict[str, Any]]: Parsed JSON data if successful, else None.
        """
        if response.status in {200, 201}:
            return await response.json()
        else:
            print(
                f"Request failed with status {response.status}: {await response.text()}"
            )
            return None

    async def find_user(
        self, username: str
    ) -> Optional[Tuple[str, str, rsa.RSAPublicKey]]:
        """
        Find a user by username.

        Args:
            username (str): The username to search for.

        Returns:
            Optional[Tuple[str, str, rsa.RSAPublicKey]]: User ID, username, and public key if found, else None.
        """
        if not self.session:
            raise RuntimeError("Session not started. Call start_session first.")

        try:
            async with self.session.get(
                f"{SERVER_URI}/user?username={username}"
            ) as response:
                data = await self._handle_response(response)
                if data and (user := data.get("user")):
                    public_key_pem = user.get("publicKey")
                    if public_key_pem:
                        recipient_public_key = serialization.load_pem_public_key(
                            public_key_pem.encode(), backend=default_backend()
                        )
                        return (
                            user.get("uid"),
                            user.get("username"),
                            recipient_public_key,
                        )
        except aiohttp.ClientError as e:
            print(f"An error occurred while finding the user: {e}")
        return None

    async def fetch_messages(self, uid: str) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch messages for a given user ID.

        Args:
            uid (str): The recipient's user ID.

        Returns:
            Optional[List[Dict[str, Any]]]: A list of messages or None if an error occurred.
        """
        if not self.session:
            raise RuntimeError("Session not started. Call start_session first.")

        try:
            async with self.session.get(
                f"{SERVER_URI}/messages?recipient={uid}"
            ) as response:
                data = await self._handle_response(response)
                return data.get("messages") if data else None
        except aiohttp.ClientError as e:
            print(f"An error occurred while fetching messages: {e}")
        return None

    async def send_message(self, sender: str, recipient: str, message: str) -> None:
        """
        Send a message from sender to recipient.

        Args:
            sender (str): The sender's username.
            recipient (str): The recipient's username.
            message (str): The message content.
        """
        if not self.session:
            raise RuntimeError("Session not started. Call start_session first.")

        try:
            async with self.session.post(
                f"{SERVER_URI}/messages",
                json={"sender": sender, "recipient": recipient, "message": message},
            ) as response:
                if response.status in (200, 201):
                    return True
                else:
                    print(f"Failed to send message: HTTP {response.status}")
                    print("Response:", await response.text())
                    return False
        except aiohttp.ClientError as e:
            print(f"An error occurred while sending the message: {e}")
            return False

    async def register_user(
        self, username: str, public_key_pem: rsa.RSAPublicKey
    ) -> None:
        """
        Register a new user with the server.

        Args:
            username (str): The username to register.
            public_key_pem (str): The public key in PEM format.
        """
        if not self.session:
            raise RuntimeError("Session not started. Call start_session first.")

        try:
            async with self.session.post(
                f"{SERVER_URI}/register",
                json={"username": username, "publicKey": public_key_pem},
            ) as response:
                if response.status in (200, 201):
                    return True
                else:
                    print(f"Failed to send message: HTTP {response.status}")
                    print("Response:", await response.text())
                    return False

        except aiohttp.ClientError as e:
            print(f"An error occurred while sending the message: {e}")
            return False


class WebSocketClient:
    def __init__(self, uri, client_id):
        self.uri = uri
        self.client_id = client_id
        self.websocket = None

    async def connect(self):
        """Connect to the WebSocket server."""
        self.websocket = await websockets.connect(self.uri)
        await self.register()

    async def register(self):
        """Register the client with the WebSocket server."""
        register_message = json.dumps({"type": "register", "clientId": self.client_id})
        await self.websocket.send(register_message)

        response = await self.websocket.recv()  # Waiting for the server's response
        return response

    async def send_message(self, recipient, message):
        """Send a message to another client."""
        message_data = {
            "type": "message",
            "sender": self.client_id,
            "recipient": recipient,
            "content": message,
        }
        await self.websocket.send(json.dumps(message_data))

    async def receive_messages(self):
        """Listen for incoming messages."""
        async for message in self.websocket:
            return message

    async def close(self):
        """Close the WebSocket connection."""
        await self.websocket.close()


async def register_user(username: str) -> None:
    """
    Register a new user with the server and generate their keys.

    Args:
        username (str): The username to register.
    """
    # Initialize the key manager and generate keys
    key_manager = RSAKeyManager(username)
    key_manager.generate_keys()
    key_manager.save_keys()

    # Send the public key to the server
    async with MessageClient() as client:
        public_key_pem = key_manager.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        response = await client.register_user(username, public_key_pem)

        if response:
            print(f"User {username} registered successfully!")
        else:
            print(f"Failed to register user {username}.")


async def start_chat(recipient: str) -> None:
    """
    Start the chat for an existing user.

    Args:
        recipient (str): The username to start the chat with.
    """
    key_manager = RSAKeyManager()
    key_manager.load_keys()

    private_key = key_manager.get_private_key()
    public_key = key_manager.get_public_key()
    username = key_manager.get_username()

    if not private_key or not public_key:
        print("Keys not found for user. Please register first.")
        return

    async with MessageClient() as client:
        user_data = await client.find_user(recipient)
        if not user_data:
            print(f"{recipient} not found.")
            return


async def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  main.py new <username>    - Register a new user")
        print("  main.py <username>        - Start chat with user")
        return

    action = sys.argv[1]

    if action == "new" and len(sys.argv) == 3:
        username = sys.argv[2]
        asyncio.run(register_user(username))
    elif len(sys.argv) == 2:
        username = (
            action  # When "new" is not the action, the username is the first argument
        )
        asyncio.run(start_chat(username))
    else:
        print("Invalid arguments.")
        print("Usage:")
        print("  main.py new <username>    - Register a new user")
        print("  main.py <username>        - Start chat with user")


if __name__ == "__main__":
    main()
