import os
import base64
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import yaml

CONFIG_DIR = "~/.config/OpenChat"
CONFIG_FILE = "config.yml"


class RSAKeyManager:
    def __init__(self, username: Optional[str] = None):
        """
        Manage RSA keys for a user, saving and loading them from disk.

        Args:
            username (str): The username for key management.
        """
        self.username = username
        self.key_dir = os.path.expanduser(CONFIG_DIR)
        os.makedirs(self.key_dir, exist_ok=True)
        self.private_key: Optional[rsa.RSAPrivateKey] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None

    def generate_keys(self) -> None:
        """
        Generate and store RSA public/private key pair.
        """
        if not self.username:
            raise ValueError("Username must be set before generating keys.")

        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        self.save_keys()

    def save_keys(self) -> None:
        """
        Save the generated RSA keys to a YAML file as base64 encoded strings.
        """
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
            file_path = f"{self.key_dir}/{CONFIG_FILE}"
            if os.path.exists(file_path):
                with open(f"{self.key_dir}/{CONFIG_FILE}", "r") as f:
                    key_data = yaml.safe_load(f)
                    raise FileExistsError(
                        f"Key file already exists for user {key_data["username"]}."
                    )
            with open(file_path, "w") as f:
                yaml.dump(key_data, f)
        except Exception as e:
            print(f"Error saving keys: {e}")

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
            self.username = key_data["username"]

            private_pem = base64.b64decode(private_key_base64)
            public_pem = base64.b64decode(public_key_base64)

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
