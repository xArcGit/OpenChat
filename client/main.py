import asyncio
import base64
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import aiohttp
import yaml
from concurrent.futures import ThreadPoolExecutor
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
  """Custom exception class for handling ChatSession-related errors."""

  def __init__(
    self, message: str, code: int = 400, details: Optional[Dict[str, Any]] = None
  ):
    """
    Initialize the ChatSessionError with a specific error message,
    optional error code, and additional details.

    Args:
        message (str): The error message to describe the issue.
        code (int, optional): An error code for categorization. Defaults to None.
        details (dict, optional): Additional context or metadata about the error. Defaults to None.
    """
    super().__init__(message)
    self.code = code
    self.details = details or {}

  def __str__(self) -> str:
    """
    Return a user-friendly string representation of the error,
    including the message, code, and details (if provided).
    """
    base_message = f"{self.__class__.__name__}: {self.args[0]}"
    if self.code:
      base_message += f" (Code: {self.code})"
    if self.details:
      base_message += f" | Details: {self.details}"
    return base_message


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
      raise ChatSessionError(
        "Username must be set before generating keys.",
        code=400,
        details={"operation": "RSA key generation"},
      )

    try:
      self.sender_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
      )
      self.sender_public_key = self.sender_private_key.public_key()

    except Exception as err:
      raise ChatSessionError(
        f"Error generating RSA keys: {err}",
        code=500,
        details={"operation": "RSA key generation"},
      )

  def save_keys(self) -> None:
    """
    Save the generated RSA keys to a YAML file as base64-encoded strings.
    """
    if not self.sender_private_key or not self.sender_public_key:
      raise ChatSessionError(
        "Keys have not been generated yet.",
        code=400,
        details={"operation": "Save RSA keys"},
      )

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
      raise ChatSessionError(
        f"Unexpected error while saving keys: {err}",
        code=500,
        details={"operation": "Save RSA keys"},
      )

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
      raise ChatSessionError(
        f"Unexpected error while checking if keys exist: {err}",
        code=500,
        details={"operation": "Check keys existence"},
      )

  def load_keys(self) -> None:
    """
    Load RSA keys and username from the YAML file.
    Raises:
        ChatSessionError: If there is an issue loading or decoding the keys.
    """
    file_path = os.path.join(self.key_dir, CONFIG_FILE)

    if not os.path.exists(file_path):
      raise ChatSessionError(
        f"Key configuration file not found at {file_path}.",
        code=400,
        details={"operation": "Load RSA keys"},
      )

    try:
      with open(file_path, "r") as f:
        key_data = yaml.safe_load(f)

      if not key_data:
        raise ChatSessionError(
          "Key configuration file is empty or malformed.",
          code=400,
          details={"operation": "Load RSA keys"},
        )

      private_key_base64 = key_data.get("private_key")
      public_key_base64 = key_data.get("public_key")
      self.sender = key_data.get("username")

      if not private_key_base64 or not public_key_base64 or not self.sender:
        raise ChatSessionError(
          "Missing required key data: private_key, public_key, or username.",
          code=400,
          details={"operation": "Load RSA keys"},
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
      raise ChatSessionError(
        f"Unexpected error loading keys: {err}",
        code=500,
        details={"operation": "Load RSA keys"},
      )

  async def encrypt_message(self, message: str) -> str:
    """
    Encrypt a message using the recipient's public key.

    Args:
        message (str): The plaintext message to encrypt.

    Returns:
        str: The Base64-encoded encrypted message.
    """

    if not self.recipient_public_key:
      raise ChatSessionError(
        "Recipient's public key is not set.",
        code=400,
        details={"operation": "Encrypt message"},
      )

    try:
      encrypted_message = await asyncio.to_thread(self._encrypt_message, message)
      return encrypted_message
    except Exception as err:
      raise ChatSessionError(
        f"Failed to encrypt the message: {err}",
        code=500,
        details={"operation": "Encrypt message"},
      )

  def _encrypt_message(self, message: str) -> str:
    """
    Helper method to perform the encryption in a separate thread.
    """
    encrypted_message = self.recipient_public_key.encrypt(
      message.encode("utf-8"),
      padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
      ),
    )
    return base64.b64encode(encrypted_message).decode("utf-8")

  async def decrypt_message(self, encrypted_message: str) -> str:
    """
    Decrypt the message using the sender's private key.
    """

    if not self.sender_private_key:
      raise ChatSessionError(
        "Sender's private key is not set.",
        code=400,
        details={"operation": "Decrypt message"},
      )

    try:
      decrypted_message = await asyncio.to_thread(
        self._decrypt_message, encrypted_message
      )
      return decrypted_message
    except Exception as err:
      raise ChatSessionError(
        f"Failed to decrypt the message: {err}",
        code=500,
        details={"operation": "Decrypt message"},
      )

  def _decrypt_message(self, encrypted_message: str) -> str:
    """
    Helper method to perform decryption in a separate thread.
    """
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

  async def connect_websocket(self):
    """
    Establish WebSocket connection.
    """
    if not self.websocket:
      try:
        self.websocket = await aiohttp.ClientSession().ws_connect(WEBSOCKET_URI)
      except Exception as err:
        raise ChatSessionError(
          f"Error connecting to WebSocket: {err}",
          code=500,
          details={"operation": "Connect WebSocket"},
        )

  async def close_websocket(self):
    """
    Close the WebSocket connection.
    """
    if self.websocket:
      await self.websocket.close()
      self.websocket = None

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
        f"Request failed with status {response.status}: {error_text}",
        code=500,
        details={"operation": "Handle HTTP response"},
      )

  async def listen_for_messages(self):
    """
    Listen for incoming WebSocket messages.
    """
    try:
      async for message in self.websocket:
        if message.type == aiohttp.WSMessageType.TEXT:
          decrypted_message = await self.decrypt_message(message.data)
          self.messages.append(f"{self.recipient}: {decrypted_message}")
        elif message.type == aiohttp.WSMessageType.ERROR:
          raise ChatSessionError("WebSocket error occurred", code=500)
    except Exception as err:
      raise ChatSessionError(
        f"Error while listening for WebSocket messages: {err}",
        code=500,
        details={"operation": "Listen for WebSocket messages"},
      )

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
        await self.websocket.send_json(message_data)
        print("Message sent via WebSocket")
      except Exception as err:
        raise ChatSessionError(
          f"An error occurred while sending the message via WebSocket: {err}",
          code=500,
          details={"operation": "Send WebSocket message"},
        )
    else:
      await self.send_message_via_api(message)

  async def send_message_via_api(self, message: str) -> None:
    """
    Send a message via the HTTP API if WebSocket is not connected.
    """
    if not self.http_session:
      raise ChatSessionError(
        "HTTP session not started. Call start_http_session first.",
        code=400,
        details={"operation": "Send HTTP message"},
      )

    if not self.sender or not self.recipient:
      raise ChatSessionError(
        "Both sender and recipient must be set before sending a message.",
        code=400,
        details={"operation": "Send HTTP message"},
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
            f"Failed to send message: {data.get('message', 'Unknown error')}",
            code=500,
            details={"operation": "Send HTTP message"},
          )
    except Exception as err:
      raise ChatSessionError(
        f"An error occurred while sending the message via API: {err}",
        code=500,
        details={"operation": "Send HTTP message"},
      )


class ChatApp:
  def __init__(self, screen, recipient: str):
    self.screen = screen
    self.recipient = recipient
    self.chat_frame = None
    self.executor = ThreadPoolExecutor(max_workers=2)  # Limit the number of threads

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

  async def __post_init__(self) -> None:
    """
    Start the chat for an existing user.
    """
    try:
      session_manager = ChatSession(self.recipient)
      await session_manager.load_keys()
      await session_manager.find_user()
      await session_manager.fetch_messages()

      # Display the previous messages
      for message in session_manager.messages:
        self.chat_output.value += f"{session_manager.recipient}: {message}\n"

    except Exception as err:
      raise ChatSessionError(
        f"Error starting chat with {self.recipient}: {err}",
        code=500,
        details={"operation": "Start chat"},
      )

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

      # Send the message in a separate thread
      self.executor.submit(self.loop.create_task, self.send_message(message))

  async def send_message(self, message: str) -> None:
    """
    Send a message, either via WebSocket or API if offline.
    """
    try:
      session_manager = ChatSession(self.recipient)
      await session_manager.send_message(message)

      # After sending, append the message to the local chat
      current_chat = self.chat_output.value or ""
      new_chat = f"{current_chat}\nYou: {message}"
      self.chat_output.value = new_chat

    except Exception as err:
      raise ChatSessionError(
        f"Error sending message: {err}", code=500, details={"operation": "Send message"}
      )

  async def receive_message(self) -> None:
    """
    Receive a message via WebSocket, decrypt it, and display it.
    """
    try:
      session_manager = ChatSession(self.recipient)
      await session_manager.receive_message()

      # Display the latest message received
      current_chat = self.chat_output.value or ""
      new_chat = (
        f"{current_chat}\n{session_manager.recipient}: {session_manager.messages[-1]}"
      )
      self.chat_output.value = new_chat

    except Exception as err:
      raise ChatSessionError(
        f"Error receiving message: {err}",
        code=500,
        details={"operation": "Receive message"},
      )

  def start_receiving_messages(self):
    """
    Start receiving messages in a separate thread.
    """
    self.executor.submit(self.loop.create_task, self.receive_message())


async def register_user(sender: str) -> None:
  """
  Register a new user with the server and generate their keys.
  """
  try:
    session_manager = ChatSession(sender=sender)
    if session_manager.keys_exist():
      raise ChatSessionError(
        "User already registered. Use existing keys.",
        code=400,
        details={"operation": "User Registration"},
      )
    else:
      session_manager.generate_keys()
      session_manager.save_keys()
      await session_manager.register_user()

  except Exception as err:
    raise ChatSessionError(
      f"Error registering user: {err}",
      code=500,
      details={"operation": "User Registration"},
    )


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
    raise ChatSessionError(
      "The screen was resized. Exiting gracefully.",
      code=400,
      details={"operation": "Resize Screen Handling"},
    )
  except StopApplication:
    raise ChatSessionError(
      "Application was stopped.",
      code=200,
      details={"operation": "Application Shutdown"},
    )
  except Exception as err:
    raise ChatSessionError(
      f"An unexpected error occurred: {err}",
      code=500,
      details={"operation": "Main Execution"},
    )
