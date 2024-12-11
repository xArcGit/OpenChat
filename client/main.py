import asyncio
import sys
from cryptography.hazmat.primitives import serialization
from src.keymanager import RSAKeyManager
from src.message import MessageClient


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
    pass


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
