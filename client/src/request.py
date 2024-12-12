import aiohttp
import websockets
import json
from typing import Optional, Dict, Any, Tuple, List
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

SERVER_URI = "http://localhost:8000"
WEBSOCKET_URI = "ws://localhost:3000"


class MessagingClient:
    def __init__(self, username: str):
        """
        MessagingClient manages communication with a remote message server and WebSocket server.
        """
        self.username = username
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None

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
        register_message = json.dumps({"type": "register", "clientId": self.username})
        await self.websocket.send(register_message)
        response = await self.websocket.recv()  # Waiting for server's response
        print(f"WebSocket registration response: {response}")

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

    async def find_user(self, username: str) -> Optional[Tuple[str, rsa.RSAPublicKey]]:
        """
        Find a user by username.
        """
        if not self.http_session:
            raise RuntimeError(
                "HTTP session not started. Call start_http_session first."
            )
        try:
            async with self.http_session.get(
                f"{SERVER_URI}/user?username={username}"
            ) as response:
                data = await self._handle_response(response)
                if data and (user := data.get("user")):
                    public_key_pem = user.get("publicKey")
                    if public_key_pem:
                        recipient_public_key = serialization.load_pem_public_key(
                            public_key_pem.encode(), backend=default_backend()
                        )
                        return recipient_public_key
        except aiohttp.ClientError as e:
            print(f"An error occurred while finding the user: {e}")
        return None

    async def fetch_messages(
        self, sender: str, recipient: str
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch messages from the server.
        """
        if not self.http_session:
            raise RuntimeError(
                "HTTP session not started. Call start_http_session first."
            )
        try:
            async with self.http_session.get(
                f"{SERVER_URI}/messages?recipient={recipient}&sender={sender}"
            ) as response:
                data = await self._handle_response(response)
                return data.get("messages") if data else None
        except aiohttp.ClientError as e:
            print(f"An error occurred while fetching messages: {e}")
        return None

    async def send_message(self, recipient: str, message: str) -> None:
        """
        Send a message either through WebSocket or fallback to HTTP API.
        """
        if self.websocket:
            # Send via WebSocket
            message_data = {
                "type": "message",
                "sender": self.username,
                "recipient": recipient,
                "content": message,
            }
            await self.websocket.send(json.dumps(message_data))
            print("Message sent via WebSocket.")
        else:
            # Fallback to API if WebSocket is not connected
            await self.send_message_via_api(recipient, message)

    async def send_message_via_api(self, recipient: str, message: str) -> None:
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
                    "sender": self.username,
                    "recipient": recipient,
                    "message": message,
                },
            ) as response:
                if response.status in (200, 201):
                    print("Message sent via API.")
                else:
                    print(f"Failed to send message via API: HTTP {response.status}")
                    print("Response:", await response.text())
        except aiohttp.ClientError as e:
            print(f"An error occurred while sending the message: {e}")

    async def register_user(self, public_key_pem: rsa.RSAPublicKey) -> None:
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
                json={"username": self.username, "publicKey": public_key_pem.decode()},
            ) as response:
                if response.status in (200, 201):
                    print("User registered successfully!")
                else:
                    print(f"Failed to register user: HTTP {response.status}")
                    print("Response:", await response.text())
        except aiohttp.ClientError as e:
            print(f"An error occurred while registering user: {e}")

    async def listen_for_messages(self):
        """
        Listen for incoming messages from the WebSocket.
        """
        try:
            async for message in self.websocket:
                print(f"Received message: {message}")
        except websockets.ConnectionClosed:
            print("WebSocket connection closed.")
