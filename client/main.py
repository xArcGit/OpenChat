import asyncio
import sys
from typing import List, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from src.manager import RSAKeyManager
from src.request import MessagingClient
from src.cryptography import RSAEncryptorDecryptor
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from asciimatics.screen import Screen
from asciimatics.scene import Scene
from asciimatics.widgets import Frame, Layout, TextBox, Text
from asciimatics.exceptions import ResizeScreenError, StopApplication
import websockets
import json


@dataclass
class ChatSession:
    recipient: str
    recipient_public_key: RSAPublicKey
    sender: str
    sender_public_key: RSAPublicKey
    sender_private_key: RSAPrivateKey
    messages: List[str]


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
            key_manager = RSAKeyManager()
            key_manager.load_keys()
            recipient_public_key: Optional[RSAPublicKey] = None
            messages: List[str] = []

            async with MessagingClient(key_manager.username) as client:
                fetched_messages = await client.get_messages(
                    key_manager.username, recipient
                )
                recipient_public_key = await client.find_user(recipient)
                if recipient_public_key is None:
                    print(f"Error: {recipient} not found.")
                    return
                if fetched_messages:
                    for message in fetched_messages:
                        for _, msg_content in message.items():
                            messages.append(msg_content)

            chat_session = ChatSession(
                recipient=recipient,
                recipient_public_key=recipient_public_key,
                sender=key_manager.username,
                sender_public_key=key_manager.public_key,
                sender_private_key=key_manager.private_key,
                messages=[],
            )
            rsa = RSAEncryptorDecryptor(
                chat_session.sender_private_key, chat_session.recipient_public_key
            )
            for msg in messages:
                decrypted_msg = rsa.decrypt_message(msg)
                chat_session.messages.append(f"{recipient}: {decrypted_msg}")

            for message in chat_session.messages:
                current_chat = self.chat_output.value or ""
                new_chat = f"{current_chat}\n{message}"
                self.chat_output.value = new_chat

        except Exception as e:
            print(f"Error starting chat with {recipient}: {e}")

    async def send_message(self, message: str) -> None:
        """
        Send a message, either via WebSocket or API if offline.
        """
        try:
            key_manager = RSAKeyManager()
            key_manager.load_keys()

            async with MessagingClient(key_manager.username) as client:
                rsa = RSAEncryptorDecryptor(
                    key_manager.private_key, key_manager.public_key
                )
                encrypted_message = rsa.encrypt_message(message)

                websocket_connected = False
                try:
                    async with websockets.connect("ws://localhost:3000") as ws:
                        websocket_connected = True
                        message_data = {
                            "type": "message",
                            "sender": key_manager.username,
                            "recipient": self.recipient,
                            "content": encrypted_message,
                        }
                        await ws.send(json.dumps(message_data))

                except (websockets.exceptions.WebSocketException, Exception):
                    websocket_connected = False

                if not websocket_connected:
                    await client.send_message(
                        key_manager.username, self.recipient, encrypted_message
                    )

        except Exception as e:
            print(f"Error sending message: {e}")

    async def receive_message(self) -> None:
        """
        Receive a message via WebSocket, decrypt it, and display it.
        """
        try:
            async with websockets.connect("ws://localhost:3000") as ws:
                while True:
                    message_data = await ws.recv()
                    message = json.loads(message_data)
                    encrypted_message = message.get("content")
                    sender = message.get("sender")
                    if encrypted_message and sender:
                        key_manager = RSAKeyManager()
                        key_manager.load_keys()
                        rsa = RSAEncryptorDecryptor(
                            key_manager.private_key, key_manager.public_key
                        )
                        decrypted_message = rsa.decrypt_message(encrypted_message)

                        current_chat = self.chat_output.value or ""
                        new_chat = f"{current_chat}\n{sender}: {decrypted_message}"
                        self.chat_output.value = new_chat

        except Exception as e:
            print(f"Error receiving message: {e}")


async def register_user(username: str) -> None:
    """
    Register a new user with the server and generate their keys.
    """
    try:
        key_manager = RSAKeyManager(username)
        if key_manager.keys_exist():
            print(
                f"Key file already exists for user {username}. Skipping key generation."
            )
        else:
            key_manager.generate_keys()

        async with MessagingClient(username) as client:
            public_key_pem = key_manager.public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            response = await client.register_user(username, public_key_pem)
            if response:
                print(f"User {username} registered successfully!")
            else:
                print(f"Failed to register user {username}.")
    except Exception as e:
        print(f"Error registering user {username}: {e}")


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
