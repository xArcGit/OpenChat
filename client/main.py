import asyncio
import base64
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import websockets
import yaml
from asciimatics.exceptions import ResizeScreenError, StopApplication
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.widgets import Frame, Layout, Text, TextBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


CONFIG_DIR = "~/.config/OpenChat"
CONFIG_FILE = "config.yml"
SERVER_URI = "http://localhost:3000"
WEBSOCKET_URI = "ws://localhost:3000"

# Define constants for RSA key generation and encryption
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048
BACKEND = default_backend()
ENCODING = Encoding.PEM
PRIVATE_FORMAT = PrivateFormat.TraditionalOpenSSL
PUBLIC_FORMAT = PublicFormat.SubjectPublicKeyInfo
ENCRYPTION_ALGORITHM = NoEncryption()
ALGORITHM = hashes.SHA256()
MGF = padding.MGF1(algorithm=ALGORITHM)
LABEL = None


@dataclass
class ChatSession:
    status: bool = False  # True if the user is online, False otherwise
    recipient: Optional[str] = None
    recipient_public_key: Optional[RSAPublicKey] = None
    sender: Optional[str] = None
    sender_public_key: Optional[RSAPublicKey] = None
    sender_private_key: Optional[RSAPrivateKey] = None
    messages: List[str] = field(default_factory=list)
    key_dir: str = os.path.expanduser(CONFIG_DIR)
    password: Optional[bytes] = None
    http_session: Optional[aiohttp.ClientSession] = None
    websocket: Optional[websockets.WebSocketClientProtocol] = None

    def __post_init__(self):
        os.makedirs(self.key_dir, exist_ok=True)

    def generate_keys(self) -> None:
        """
        Generate and store RSA public/private key pair.
        """
        if not self.sender:
            raise ValueError("Username must be set before generating keys.")

        self.sender_private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE, backend=BACKEND
        )
        self.sender_public_key = self.sender_private_key.public_key()

    def save_keys(self) -> None:
        """
        Save the generated RSA keys to a YAML file as base64 encoded strings.
        """
        if not self.sender_private_key or not self.sender_public_key:
            raise ValueError("Keys have not been generated yet.")

        private_pem = self.sender_private_key.private_bytes(
            encoding=ENCODING,
            format=PRIVATE_FORMAT,
            encryption_algorithm=ENCRYPTION_ALGORITHM,
        )

        public_pem = self.sender_public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PUBLIC_FORMAT,
        )

        private_key_base64 = base64.b64encode(private_pem).decode("utf-8")
        public_key_base64 = base64.b64encode(public_pem).decode("utf-8")

        key_data = {
            "username": self.sender,
            "private_key": private_key_base64,
            "public_key": public_key_base64,
        }

        try:
            file_path = f"{self.key_dir}/{CONFIG_FILE}"
            with open(file_path, "w") as f:
                yaml.dump(key_data, f)
        except Exception as err:
            raise ValueError(f"Error saving keys to YAML: {err}")

    def keys_exist(self) -> bool:
        """
        Check if the keys already exist for the user in the config file.

        Returns:
            bool: True if keys exist, False otherwise.
        """
        file_path = f"{self.key_dir}/{CONFIG_FILE}"
        if os.path.exists(file_path):
            return True
        return False

    def load_keys(self) -> None:
        """
        Load RSA keys and username from the YAML file.
        """
        try:
            with open(f"{self.key_dir}/{CONFIG_FILE}", "r") as f:
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
            self.sender = key_data["username"]

            private_pem = base64.b64decode(private_key_base64)
            public_pem = base64.b64decode(public_key_base64)

            self.sender_private_key = load_pem_private_key(
                private_pem, password=self.password, backend=BACKEND
            )

            self.sender_public_key = load_pem_public_key(public_pem, backend=BACKEND)

        except Exception as err:
            raise ValueError(f"Error loading keys from YAML: {err}")

    def encrypt_message(self, message: str) -> str:
        """
        Encrypt a message using the public key.

        Args:
          message (str): The message to encrypt.

        Returns:
          str: The Base64 encoded encrypted message.
        """
        encrypted_message = self.recipient_public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=MGF,
                algorithm=ALGORITHM,
                label=LABEL,
            ),
        )
        return base64.b64encode(encrypted_message).decode("utf-8")

    def decrypt_message(self, message: str) -> str:
        """
        Decrypt a message using the private key.

        Args:
          message (str): The Base64 encoded encrypted message.

        Returns:
          str: The decrypted message.
        """
        encrypted_message = base64.b64decode(message)
        decrypted_message = self.sender_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=MGF,
                algorithm=ALGORITHM,
                label=LABEL,
            ),
        )
        return decrypted_message.decode("utf-8")

    async def __aenter__(self):
        """
        Enter async context manager to start both HTTP session and WebSocket.
        """
        await self.start_http_session()
        await self.connect_websocket()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """
        Exit async context manager and close the sessions.
        """
        await self.close_http_session()
        await self.close_websocket()

    async def start_http_session(self):
        """
        Start a persistent aiohttp session for HTTP requests.
        """
        if not self.http_session:
            self.http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )

    async def close_http_session(self):
        """
        Close the HTTP session.
        """
        if self.http_session:
            await self.http_session.close()
            self.http_session = None

    async def connect_websocket(self):
        """
        Connect to the WebSocket server.
        """
        self.websocket = await websockets.connect(WEBSOCKET_URI)
        await self.register_websocket()

    async def close_websocket(self):
        """
        Close the WebSocket connection.
        """
        if self.websocket:
            await self.websocket.close()
            self.websocket = None

    async def register_websocket(self):
        """
        Register the client with the WebSocket server.
        """
        register_message = json.dumps({"type": "register", "clientId": self.sender})
        await self.websocket.send(register_message)
        response = await self.websocket.recv()
        return response

    async def _handle_response(
        self, response: aiohttp.ClientResponse
    ) -> Optional[Dict[str, Any]]:
        """
        Handle the response from an HTTP request.
        """
        if response.status in {200, 201}:
            return await response.json()
        else:
            print(
                f"Request failed with status {response.status}: {await response.text()}"
            )
            return None

    async def find_user(self) -> Optional[Tuple[str, rsa.RSAPublicKey]]:
        """
        Find a user by username.
        """
        if not self.http_session:
            raise RuntimeError(
                "HTTP session not started. Call start_http_session first."
            )
        try:
            async with self.http_session.get(
                f"{SERVER_URI}/user?username={self.recipient}"
            ) as response:
                data = await self._handle_response(response)
                if data and (user := data.get("user")):
                    public_key_pem = user.get("publicKey")
                    if public_key_pem:
                        self.recipient_public_key = load_pem_public_key(
                            public_key_pem.encode(), backend=BACKEND
                        )
        except aiohttp.ClientError as err:
            raise RuntimeError(f"An error occurred while finding user: {err}")

    async def send_message(self, message: str) -> None:
        """
        Send a message either through WebSocket or fallback to HTTP API.
        """
        if self.websocket:
            message_data = {
                "type": "message",
                "sender": self.sender,
                "recipient": self.recipient,
                "content": message,
            }
            await self.websocket.send(json.dumps(message_data))
            print("Message sent via WebSocket.")
        else:
            await self.send_message_via_api(message)

    async def send_message_via_api(self, message: str) -> None:
        """
        Send message via HTTP API if WebSocket is not connected.
        """
        if not self.http_session:
            raise RuntimeError(
                "HTTP session not started. Call start_http_session first."
            )
        try:
            async with self.http_session.post(
                f"{SERVER_URI}/messages",
                json={
                    "sender": self.sender,
                    "recipient": self.recipient,
                    "message": message,
                },
            ) as response:
                if response.status in (200, 201):
                    return True
                return False

        except aiohttp.ClientError as err:
            raise RuntimeError(
                f"An error occurred while sending message via API: {err}"
            )

    async def fetch_messages(self) -> Optional[List[str]]:
        """
        Fetch messages from the server.
        """
        if not self.http_session:
            raise RuntimeError(
                "HTTP session not started. Call start_http_session first."
            )
        try:
            async with self.http_session.get(
                f"{SERVER_URI}/messages?recipient={self.recipient}&sender={self.sender}"
            ) as response:
                data = await self._handle_response(response)
                return data.get("messages") if data else None
        except aiohttp.ClientError as err:
            raise RuntimeError(f"An error occurred while fetching messages: {err}")

    async def register_user(self) -> None:
        """
        Register a new user with the server.
        """
        if not self.http_session:
            raise RuntimeError(
                "HTTP session not started. Call start_http_session first."
            )
        try:
            async with self.http_session.post(
                f"{SERVER_URI}/register",
                json={
                    "username": self.sender,
                    "publicKey": self.sender_public_key.decode(),
                },
            ) as response:
                if response.status in (200, 201):
                    return True
                return False

        except aiohttp.ClientError as err:
            raise RuntimeError(f"An error occurred while registering user: { err }")

    async def listen_for_messages(self):
        """
        Listen for incoming messages from the WebSocket.
        """
        try:
            async for message in self.websocket:
                return message
        except websockets.ConnectionClosed:
            raise RuntimeError("WebSocket connection closed.")


class ChatApp:
    def __init__(self, screen, recipient: str):
        self.screen = screen
        self.recipient = recipient
        self.chat_frame = None

    def create_chat_frame(self):
        self.chat_frame = ChatFrame(self.screen, self.recipient)
        self.screen.play([Scene([self.chat_frame], -1)])


class ChatFrame(Frame):
    def __init__(self, screen, recipient: str):
        super(ChatFrame, self).__init__(
            screen,
            screen.height,
            screen.width,
            has_border=True,
            title=f"Chat with {recipient}",
        )
        self.recipient = recipient
        layout = Layout([1], fill_frame=True)
        self.add_layout(layout)

        self.chat_output = TextBox(
            height=screen.height - 5,
            as_string=True,
            readonly=True,
            line_wrap=True,
        )
        layout.add_widget(self.chat_output)

        self.chat_input = Text("/>", on_change=self.on_input_change)
        layout.add_widget(self.chat_input)

        self.fix()

        self.loop = asyncio.get_event_loop()
        self.loop.create_task(self.start_chat(recipient))

    def on_input_change(self):
        pass

    def on_submit(self):
        message = self.chat_input.value
        if message:
            current_chat = self.chat_output.value or ""
            new_chat = f"{current_chat}\nYou: {message}"
            self.chat_output.value = new_chat
            self.chat_input.value = ""
            self.scene.force_update = True

            self.loop.create_task(self.send_message(message))

    async def start_chat(self, recipient: str) -> None:
        """
        Start the chat for an existing user.
        """
        try:
            session_manager = ChatSession()
            session_manager.recipient = recipient
            session_manager.load_keys()
            session_manager.find_user()
            session_manager.fetch_messages()
            # TODO: Need to Add

        except Exception as e:
            print(f"Error starting chat with {recipient}: {e}")

    async def send_message(self, message: str) -> None:
        """
        Send a message, either via WebSocket or API if offline.
        """
        try:
            async with ChatSession() as session_manager:
                encrypted_message = session_manager.encrypt_message(message)

                websocket_connected = False
                try:
                    async with websockets.connect(WEBSOCKET_URI) as ws:
                        websocket_connected = True
                        message_data = {
                            "type": "message",
                            "sender": session_manager.sender,
                            "recipient": self.recipient,
                            "content": encrypted_message,
                        }
                        await ws.send(json.dumps(message_data))

                except (websockets.exceptions.WebSocketException, Exception):
                    websocket_connected = False

                if not websocket_connected:
                    await session_manager.send_message(encrypted_message)

        except Exception as e:
            print(f"Error sending message: {e}")

    async def receive_message(self) -> None:
        """
        Receive a message via WebSocket, decrypt it, and display it.
        """
        try:
            async with websockets.connect(WEBSOCKET_URI) as ws:
                while True:
                    message_data = await ws.recv()
                    message = json.loads(message_data)
                    encrypted_message = message.get("content")
                    sender = message.get("sender")
                    if encrypted_message and sender:
                        session_manager = ChatSession()
                        decrypted_message = session_manager.decrypt_message(
                            encrypted_message
                        )

                        current_chat = self.chat_output.value or ""
                        new_chat = f"{current_chat}\n{sender}: {decrypted_message}"
                        self.chat_output.value = new_chat

        except Exception as e:
            print(f"Error receiving message: {e}")


async def register_user(sender: str) -> None:
    """
    Register a new user with the server and generate their keys.
    """
    try:
        session_manager = ChatSession(sender=sender)
        if session_manager.keys_exist():
            return False
        else:
            session_manager.generate_keys()
            session_manager.save_keys()
            session_manager.register_user()

    except Exception as err:
        raise RuntimeError(f"Error registering user: {err}")


async def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  main.py new <username>    - Register a new user")
        print("  main.py <username>        - Start chat with user")

    action = sys.argv[1]

    if action == "new" and len(sys.argv) == 3:
        username = sys.argv[2]
        await register_user(username)
    elif len(sys.argv) == 2:
        username = action
        Screen.wrapper(lambda s: ChatApp(s, username).create_chat_frame())

    else:
        print("Invalid arguments.")
        print("Usage:")
        print("  main.py new <username>    - Register a new user")
        print("  main.py <username>        - Start chat with user")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except ResizeScreenError:
        print("The screen was resized. Exiting gracefully.")
    except StopApplication:
        print("Application was stopped.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
