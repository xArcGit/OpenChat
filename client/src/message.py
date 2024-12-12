import aiohttp
from typing import Optional, Dict, Any, Tuple, List
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

SERVER_URI = "http://localhost:3000"


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
                timeout=aiohttp.ClientTimeout(total=10)  # 5-second timeout
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

    async def find_user(self, username: str) -> Optional[Tuple[str, rsa.RSAPublicKey]]:
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
                        return (recipient_public_key,)
        except aiohttp.ClientError as e:
            print(f"An error occurred while finding the user: {e}")
        return None

    async def fetch_messages(
        self, sender: str, recipient: str
    ) -> Optional[List[Dict[str, Any]]]:
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
                f"{SERVER_URI}/messages?recipient={recipient}&sender={sender}"
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
