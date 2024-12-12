import asyncio
import sys
from typing import List, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from src.keymanager import RSAKeyManager
from src.message import MessageClient
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey


@dataclass
class ChatSession:
    recipient: str
    recipient_public_key: RSAPublicKey
    sender: str
    sender_public_key: RSAPublicKey
    sender_private_key: RSAPrivateKey
    messages: List[str]  # Assuming messages are just strings


async def start_chat(recipient: str) -> None:
    """
    Start the chat for an existing user.

    Args:
        recipient (str): The recipient to start the chat with.
    """
    try:
        key_manager = RSAKeyManager()
        key_manager.load_keys()
        recipient_public_key: Optional[RSAPublicKey] = None
        messages: List[str] = []

        async with MessageClient() as client:
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
                        messages.append(msg_content)  # Append message content

        chat_session = ChatSession(
            recipient=recipient,
            recipient_public_key=recipient_public_key,
            sender=key_manager.username,
            sender_public_key=key_manager.public_key,
            sender_private_key=key_manager.private_key,
            messages=messages,
        )

        print(f"Starting chat with {recipient}...")
        for msg in chat_session.messages:
            print(msg)

    except Exception as e:
        print(f"Error starting chat with {recipient}: {e}")


async def register_user(username: str) -> None:
    """
    Register a new user with the server and generate their keys.

    Args:
        username (str): The username to register.
    """
    try:
        key_manager = RSAKeyManager(username)
        key_manager.generate_keys()
        key_manager.save_keys()

        async with MessageClient() as client:
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
        username = (
            action  # When "new" is not the action, the username is the first argument
        )
        await start_chat(username)
    else:
        print("Invalid arguments.")
        print("Usage:")
        print("  main.py new <username>    - Register a new user")
        print("  main.py <username>        - Start chat with user")


if __name__ == "__main__":
    asyncio.run(main())
