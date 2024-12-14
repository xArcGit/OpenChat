import asyncio
import base64
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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
from cryptography.hazmat.primitives import serialization


CONFIG_DIR = os.path.expanduser("~/.config/OpenChat")
CONFIG_FILE = "config.yml"
SERVER_URI = "http://localhost:3000"
WEBSOCKET_URI = "ws://localhost:3000"


class ChatSessionError(Exception):
  """Custom exception class for ChatSession errors."""

  pass


@dataclass
class ChatSession:
  status: bool = False  # True if the user is online, False otherwise
  recipient: Optional[str] = None
  recipient_public_key: Optional[rsa.RSAPublicKey] = None
  sender: Optional[str] = None
  sender_public_key: Optional[rsa.RSAPublicKey] = None
  sender_private_key: Optional[rsa.RSAPrivateKey] = None
  messages: List[str] = field(default_factory=list)
  key_dir: str = CONFIG_DIR
  password: Optional[bytes] = None
  http_session: Optional[aiohttp.ClientSession] = None
  websocket: Optional[Any] = None

  def __post_init__(self):
    os.makedirs(self.key_dir, exist_ok=True)

  def generate_keys(self) -> None:
    """
    Generate and store an RSA public/private key pair.
    """
    if not self.sender:
      raise ChatSessionError("Username must be set before generating keys.")

    try:
      self.sender_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
      )
      self.sender_public_key = self.sender_private_key.public_key()

    except Exception as err:
      raise ChatSessionError(f"Error generating RSA keys: {err}")

  def save_keys(self) -> None:
    """
    Save the generated RSA keys to a YAML file as base64-encoded strings.
    """
    if not self.sender_private_key or not self.sender_public_key:
      raise ChatSessionError("Keys have not been generated yet.")

    try:
      private_pem = self.sender_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
      )

      public_pem = self.sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
      )

      private_key_base64 = base64.b64encode(private_pem).decode("utf-8")
      public_key_base64 = base64.b64encode(public_pem).decode("utf-8")

      key_data = {
        "username": self.sender,
        "private_key": private_key_base64,
        "public_key": public_key_base64,
      }

      os.makedirs(self.key_dir, exist_ok=True)
      file_path = os.path.join(self.key_dir, CONFIG_FILE)
      with open(file_path, "w") as f:
        yaml.dump(key_data, f, default_flow_style=False)

    except Exception as err:
      raise ChatSessionError(f"Unexpected error while saving keys: {err}")

  def keys_exist(self) -> bool:
    """
    Check if the keys and username exist in the config file.

    Returns:
        bool: True if keys and username exist and are valid, False otherwise.
    """
    file_path = os.path.join(self.key_dir, CONFIG_FILE)

    if not os.path.exists(file_path):
      return False

    try:
      with open(file_path, "r") as f:
        key_data = yaml.safe_load(f)

      if not key_data:
        return False

      required_fields = ["private_key", "public_key", "username"]
      return all(field in key_data for field in required_fields)

    except Exception as err:
      raise ChatSessionError(f"Unexpected error while saving keys: {err}")

  def load_keys(self) -> None:
    """
    Load RSA keys and username from the YAML file.

    Raises:
        ChatSessionError: If there is an issue loading or decoding the keys.
    """
    file_path = os.path.join(self.key_dir, CONFIG_FILE)

    if not os.path.exists(file_path):
      raise ChatSessionError(f"Key configuration file not found at {file_path}.")

    try:
      with open(file_path, "r") as f:
        key_data = yaml.safe_load(f)

      if not key_data:
        raise ChatSessionError("Key configuration file is empty or malformed.")

      private_key_base64 = key_data.get("private_key")
      public_key_base64 = key_data.get("public_key")
      self.sender = key_data.get("username")

      if not private_key_base64 or not public_key_base64 or not self.sender:
        raise ChatSessionError(
          "Missing required key data: private_key, public_key, or username."
        )

      private_pem = base64.b64decode(private_key_base64)
      public_pem = base64.b64decode(public_key_base64)

      self.sender_private_key = serialization.load_pem_private_key(
        private_pem, password=self.password, backend=default_backend()
      )
      self.sender_public_key = serialization.load_pem_public_key(
        public_pem, backend=default_backend()
      )

    except Exception as err:
      raise ChatSessionError(f"Unexpected error loading keys: {err}")

  async def encrypt_message(self, message: str) -> str:
    """
    Encrypt a message using the recipient's public key.
    (Assuming this method is async-friendly or can be adjusted to run in a non-blocking way)

    Args:
        message (str): The plaintext message to encrypt.

    Returns:
        str: The Base64-encoded encrypted message.
    """

    def encrypt():
      if not self.recipient_public_key:
        raise ChatSessionError("Recipient's public key is not set.")

      try:
        encrypted_message = self.recipient_public_key.encrypt(
          message.encode("utf-8"),
          padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
          ),
        )
        return base64.b64encode(encrypted_message).decode("utf-8")

      except Exception as err:
        raise ChatSessionError(f"Failed to encrypt the message: {err}")

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(self.executor, encrypt)

  async def decrypt_message(self, encrypted_message: str) -> str:
    """
    Decrypt the message using the sender's private key.
    This method will run in a separate thread.
    """

    def decrypt():
      if not self.sender_private_key:
        raise ChatSessionError("Sender's private key is not set.")

      try:
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted_message = self.sender_private_key.decrypt(
          encrypted_bytes,
          padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
          ),
        )
        return decrypted_message.decode("utf-8")

      except Exception as err:
        raise ChatSessionError(f"Failed to decrypt the message: {err}")

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(self.executor, decrypt)

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
      self.http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))

  async def close_http_session(self):
    """
    Close the HTTP session.
    """
    if self.http_session:
      await self.http_session.close()
      self.http_session = None

  async def _handle_response(
    self, response: aiohttp.ClientResponse
  ) -> Optional[Dict[str, Any]]:
    """
    Handle the response from an HTTP request.
    """
    if response.status in {200, 201}:
      return await response.json()
    else:
      error_text = await response.text()
      raise ChatSessionError(
        f"Request failed with status {response.status}: {error_text}"
      )

  async def register_user(self) -> None:
    """
    Register the sender user via HTTP API.
    """
    if not self.http_session:
      raise ChatSessionError("HTTP session not started. Call start_http_session first.")

    if not self.sender or not self.sender_public_key:
      raise ChatSessionError("Sender username or public key is not set.")

    try:
      async with self.http_session.post(
        f"{SERVER_URI}/register",
        json={
          "username": self.sender,
          "publicKey": self.sender_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
          ).decode("utf-8"),
        },
      ) as response:
        data = await self._handle_response(response)
        if data.get("status") != "success":
          raise ChatSessionError(
            "Registration failed: " + data.get("message", "Unknown error")
          )
    except Exception as err:
      raise ChatSessionError(f"An error occurred during registration: {err}")

  async def find_user(self) -> None:
    """
    Retrieve the recipient's public key by username via HTTP API.
    """
    if not self.http_session:
      raise ChatSessionError("HTTP session not started. Call start_http_session first.")

    if not self.recipient:
      raise ChatSessionError("Recipient username is not set.")

    try:
      async with self.http_session.get(
        f"{SERVER_URI}/user?username={self.recipient}"
      ) as response:
        data = await self._handle_response(response)
        if not data or "user" not in data:
          raise ChatSessionError("Recipient user not found.")

        public_key_pem = data["user"].get("publicKey")
        if not public_key_pem:
          raise ChatSessionError("Recipient public key is missing.")

        self.recipient_public_key = serialization.load_pem_public_key(
          public_key_pem.encode("utf-8"), backend=default_backend()
        )
    except Exception as err:
      raise ChatSessionError(f"An error occurred while finding the user: {err}")

  async def send_message_via_api(self, message: str) -> None:
    """
    Send a message via the HTTP API if WebSocket is not connected.

    Args:
        message (str): The message to send.

    Raises:
        ChatSessionError: If the HTTP session is not started or if the API request fails.
    """
    if not self.http_session:
      raise ChatSessionError("HTTP session not started. Call start_http_session first.")

    if not self.sender or not self.recipient:
      raise ChatSessionError(
        "Both sender and recipient must be set before sending a message."
      )

    try:
      encrypted_message = await self.encrypt_message(message)

      async with self.http_session.post(
        f"{SERVER_URI}/messages",
        json={
          "sender": self.sender,
          "recipient": self.recipient,
          "message": encrypted_message,
        },
      ) as response:
        data = await self._handle_response(response)

        if data.get("status") != "success":
          raise ChatSessionError(
            f"Failed to send message: {data.get('message', 'Unknown error')}"
          )

    except Exception as err:
      raise ChatSessionError(
        f"An error occurred while sending the message via API: {err}"
      )

  async def fetch_messages(self) -> Optional[List[str]]:
    """
    Fetch messages from the server asynchronously and decrypt them using a thread pool.
    """
    if not self.http_session:
      raise ChatSessionError("HTTP session not started. Call start_http_session first.")

    if not self.recipient or not self.sender:
      raise ChatSessionError("Both sender and recipient must be set to fetch messages.")

    try:
      async with self.http_session.get(
        f"{SERVER_URI}/messages?recipient={self.recipient}&sender={self.sender}"
      ) as response:
        data = await self._handle_response(response)
        messages = data.get("messages") if data else []
        if not isinstance(messages, list):
          raise ChatSessionError("Invalid response format: 'messages' is not a list.")

        decrypted_messages = await asyncio.gather(
          *(self.decrypt_message(message) for message in messages)
        )
        for decrypted_message in decrypted_messages:
          self.messages.append(f"{self.recipient}: {decrypted_message}")

    except Exception as err:
      raise ChatSessionError(f"An error occurred while fetching messages: {err}")

  async def close_websocket(self):
    """
    Gracefully close the WebSocket connection.
    """
    if self.websocket:
      try:
        await self.websocket.close()
        self.websocket = None
      except websockets.WebSocketException as err:
        raise ChatSessionError(f"Error closing WebSocket connection: {err}")

  async def connect_websocket(self):
    """
    Connect to the WebSocket server.
    """
    if not self.websocket_uri:
      raise ChatSessionError("WebSocket URI is not set.")

    try:
      self.websocket = await websockets.connect(self.websocket_uri)
      await self.register_websocket()

    except websockets.ConnectionClosedError as err:
      raise ChatSessionError(f"WebSocket connection failed: {err}")
    except Exception as err:
      raise ChatSessionError(f"Failed to connect to WebSocket: {err}")

  async def register_websocket(self):
    """
    Register the client with the WebSocket server.
    """
    if not self.sender:
      raise ChatSessionError("Sender username is not set.")

    register_message = json.dumps({"type": "register", "clientId": self.sender})
    try:
      await self.websocket.send(register_message)
      response = await asyncio.wait_for(self.websocket.recv(), timeout=10)
      response_data = json.loads(response)
      if response_data.get("status") != "success":
        raise ChatSessionError(
          f"Registration failed: {response_data.get('message', 'Unknown error')}"
        )

    except asyncio.TimeoutError:
      raise ChatSessionError(
        "Timeout occurred while waiting for WebSocket registration response."
      )
    except websockets.WebSocketException as err:
      raise ChatSessionError(f"WebSocket error during registration: {err}")
    except json.JSONDecodeError:
      raise ChatSessionError(
        "Received invalid JSON response from the WebSocket server."
      )
    except Exception as err:
      raise ChatSessionError(f"An error occurred during WebSocket registration: {err}")

  async def send_message(self, message: str) -> None:
    """
    Send a message either through WebSocket or fallback to HTTP API.
    """
    if self.websocket:
      try:
        self.messages.append(f"You: {message}")
        encrypted_message = await self.encrypt_message(message)
        message_data = {
          "type": "message",
          "sender": self.sender,
          "recipient": self.recipient,
          "content": encrypted_message,
        }
        await self.websocket.send(json.dumps(message_data))
        print("Message sent via WebSocket")
      except Exception as err:
        raise ChatSessionError(
          f"An error occurred while sending the message via WebSocket: {err}"
        )
    else:
      await self.send_message_via_api(message)

  async def receive_message(self) -> None:
    """
    Receive a message via WebSocket, decrypt it, and display it.
    """
    if not self.websocket:
      raise ChatSessionError("WebSocket is not connected.")

    try:
      async for message in self.websocket:
        message_data = json.loads(message)
        encrypted_message = message_data.get("content")
        sender = message_data.get("sender")
        if encrypted_message and sender:
          decrypted_message = await self.decrypt_message(encrypted_message)
          self.messages.append(f"{self.recipient}: {decrypted_message}")

    except Exception as err:
      raise ChatSessionError(f"Error receiving message: {err}")


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

  async def __post_init__(self, recipient: str) -> None:
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

    except Exception as err:
      raise ChatSessionError(f"Error starting chat with {recipient}: {err}")

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

  async def send_message(self, message: str) -> None:
    """
    Send a message, either via WebSocket or API if offline.
    """
    try:
      async with ChatSession() as session_manager:
        session_manager.send_message(message)

    except Exception as err:
      raise ChatSessionError(f"Error sending message: {err}")

  async def receive_message(self) -> None:
    """
    Receive a message via WebSocket, decrypt it, and display it.
    """
    try:
      async with ChatSession() as session_manager:
        await session_manager.receive_message()
        current_chat = self.chat_output.value or ""
        new_chat = (
          f"{current_chat}\n{session_manager.recipient}: {session_manager.messages[-1]}"
        )
        self.chat_output.value = new_chat

    except Exception as err:
      raise ChatSessionError(f"Error receiving message: {err}")


async def register_user(sender: str) -> None:
  """
  Register a new user with the server and generate their keys.
  """
  try:
    session_manager = ChatSession(sender=sender)
    if session_manager.keys_exist():
      raise ChatSessionError("User already registered. Use existing keys.")
    else:
      session_manager.generate_keys()
      session_manager.save_keys()
      session_manager.register_user()

  except Exception as err:
    raise ChatSessionError(f"Error registering user: {err}")


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
    raise ChatSessionError("The screen was resized. Exiting gracefully.")
  except StopApplication:
    raise ChatSessionError("Application was stopped.")
  except Exception as err:
    raise ChatSessionError(f"An unexpected error occurred: {err}")
