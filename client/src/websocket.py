import websockets
import json

WEBSOCKET_URI = "ws://localhost:3000"


class WebSocketClient:
    def __init__(self, uri, sender):
        self.uri = uri
        self.sender = sender
        self.websocket = None

    async def connect(self):
        """Connect to the WebSocket server."""
        self.websocket = await websockets.connect(self.uri)
        await self.register()

    async def register(self):
        """Register the client with the WebSocket server."""
        register_message = json.dumps({"type": "register", "clientId": self.sender})
        await self.websocket.send(register_message)

        response = await self.websocket.recv()  # Waiting for the server's response
        return response

    async def send_message(self, recipient, message):
        """Send a message to another client."""
        message_data = {
            "type": "message",
            "sender": self.sender,
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
