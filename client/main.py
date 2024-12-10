#!/usr/bin/env python3
import aiohttp
import asyncio
import base64
import json
import os
import sys
import websockets
import yaml
import threading
import curses
from typing import Optional, Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

SERVER_URI = "http://localhost:3000"
WEBSOCKET_URI = "ws://localhost:3000"


class RSAKeyManager:
    def __init__(self, username: Optional[str] = None):
        self.username = username
        self.key_dir = "keys"
        os.makedirs(self.key_dir, exist_ok=True)
        self.private_key: Optional[rsa.RSAPrivateKey] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None

    def generate_keys(self) -> None:
        if not self.username:
            raise ValueError("Username must be set before generating keys.")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.save_keys()

    def save_keys(self) -> None:
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
        try:
            with open(f"{self.key_dir}/conf.yml", "r") as f:
                key_data = yaml.safe_load(f)

            if not key_data:
                raise ValueError("No key data found in the YAML file.")

            self.username = key_data["username"]
            private_pem = base64.b64decode(key_data["private_key"])
            public_pem = base64.b64decode(key_data["public_key"])

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
        self.private_key = private_key
        self.public_key = public_key

    def encrypt_message(self, message: str) -> str:
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
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        await self.start_session()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close_session()

    async def start_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5))

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def _handle_response(
        self, response: aiohttp.ClientResponse
    ) -> Optional[Dict[str, Any]]:
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


class WebSocketClient:
    def __init__(self, uri, client_id):
        self.uri = uri
        self.client_id = client_id
        self.websocket = None

    async def connect(self):
        self.websocket = await websockets.connect(self.uri)
        await self.register()

    async def register(self):
        register_message = json.dumps({"type": "register", "clientId": self.client_id})
        await self.websocket.send(register_message)

    async def send_message(self, recipient, message):
        message_data = {
            "type": "message",
            "sender": self.client_id,
            "recipient": recipient,
            "content": message,
        }
        await self.websocket.send(json.dumps(message_data))

    async def receive_messages(self):
        async for message in self.websocket:
            return message

    async def close(self):
        await self.websocket.close()


class ChatUI:
    def __init__(self, stdscr, client, websocket, encryptor, username, recipient):
        self.stdscr = stdscr
        self.client = client
        self.websocket = websocket
        self.encryptor = encryptor
        self.username = username
        self.recipient = recipient
        self.input_text = ""
        self.received_messages = []

    def display_messages(self):
        height, width = self.stdscr.getmaxyx()
        message_window = curses.newwin(height - 3, width, 0, 0)
        message_window.scrollok(True)
        message_window.clear()

        for idx, message in enumerate(self.received_messages[-(height - 3) :]):
            message_window.addstr(idx, 0, message)

        message_window.refresh()

    def handle_input(self):
        self.stdscr.clear()
        self.display_messages()
        self.stdscr.refresh()

        input_window = curses.newwin(
            3, self.stdscr.getmaxyx()[1], self.stdscr.getmaxyx()[0] - 3, 0
        )
        input_window.clear()
        input_window.addstr(0, 0, ": " + self.input_text)
        input_window.refresh()

        key = self.stdscr.getch()

        if key == curses.KEY_ENTER or key == 10:
            if self.input_text.strip():
                self.received_messages.append(f"{self.username}: {self.input_text}")
                encrypted_message = self.encryptor.encrypt_message(self.input_text)
                asyncio.create_task(
                    self.websocket.send_message(self.recipient, encrypted_message)
                )
                self.input_text = ""
            self.display_messages()

        elif key == 27:
            return False

        elif key == curses.KEY_BACKSPACE or key == 127:
            self.input_text = self.input_text[:-1]
        else:
            self.input_text += chr(key) if 32 <= key <= 126 else ""

        return True

    async def chat_loop(self):
        while True:
            self.display_messages()
            if not self.handle_input():
                break

            message = await self.websocket.receive_messages()
            if message:
                decrypted_message = self.encryptor.decrypt_message(message["content"])
                self.received_messages.append(f"{self.recipient}: {decrypted_message}")
                self.display_messages()


async def start_chat(recipient: str) -> None:
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

        websocket = WebSocketClient(WEBSOCKET_URI, username)
        await websocket.connect()

        encryptor = RSAEncryptorDecryptor(private_key, public_key)

        # Run the UI in a separate thread to avoid blocking
        threading.Thread(
            target=run_ui_thread,
            args=(None, client, websocket, encryptor, username, recipient),
        ).start()


async def register_user(username: str) -> None:
    key_manager = RSAKeyManager(username)
    key_manager.generate_keys()  # Generate public/private keys for the user

    private_key = key_manager.get_private_key()  # noqa: F841
    public_key = key_manager.get_public_key()

    # Send the public key to the server
    async with MessageClient() as client:
        user_data = {
            "username": username,
            "publicKey": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8"),
        }

        try:
            async with client.session.post(
                f"{SERVER_URI}/register", json=user_data
            ) as response:
                data = await client._handle_response(response)
                if data:
                    print(f"User {username} registered successfully!")
                else:
                    print(f"Failed to register user {username}.")
        except Exception as e:
            print(f"Error during registration: {e}")


def run_ui_thread(stdscr, client, websocket, encryptor, username, recipient):
    # Create the ChatUI instance with stdscr
    ui = ChatUI(stdscr, client, websocket, encryptor, username, recipient)

    # Schedule the chat_loop coroutine to run in the current event loop
    asyncio.create_task(ui.chat_loop())  # Schedule it without running a new event loop

    while True:
        try:
            # Run the event loop until interrupted
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            break  # Allow clean exit on keyboard interrupt


async def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  main.py new <username>    - Register a new user")
        print("  main.py <username>        - Start chat with user")
        return

    action = sys.argv[1]

    if action == "new" and len(sys.argv) == 3:
        username = sys.argv[2]
        await register_user(username)
    elif len(sys.argv) == 2:
        recipient = action
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

            websocket = WebSocketClient(WEBSOCKET_URI, username)
            await websocket.connect()

            encryptor = RSAEncryptorDecryptor(private_key, public_key)

            curses.wrapper(
                run_ui_thread, client, websocket, encryptor, username, recipient
            )

    else:
        print("Invalid arguments.")
        print("Usage:")
        print("  main.py new <username>    - Register a new user")
        print("  main.py <username>        - Start chat with user")


if __name__ == "__main__":
    asyncio.run(main())
