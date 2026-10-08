import base64
import os

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecureSession:

    def __init__(self):
        # Generate X25519 private key
        self.private_key = x25519.X25519PrivateKey.generate()

        # Generate X25519 public key
        self.public_key = self.private_key.public_key()

        # Session key will be generated after receiving
        # the other user's public key
        self.session_key = None

    # ==========================================
    # GET PUBLIC KEY
    # ==========================================

    def get_public_key(self):

        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return base64.b64encode(
            public_bytes
        ).decode("utf-8")

    # ==========================================
    # GENERATE SESSION KEY
    # ==========================================

    def generate_session_key(self, peer_public_key):

        peer_public_bytes = base64.b64decode(
            peer_public_key
        )

        peer_key = x25519.X25519PublicKey.from_public_bytes(
            peer_public_bytes
        )

        # X25519 Diffie-Hellman
        shared_secret = self.private_key.exchange(
            peer_key
        )

        # Derive a 256-bit AES key
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"LAN_CHAT_SESSION_KEY"
        ).derive(
            shared_secret
        )

        return self.session_key

    # ==========================================
    # ENCRYPT MESSAGE
    # ==========================================

    def encrypt_message(self, message):

        if self.session_key is None:
            raise Exception(
                "Secure session has not been established"
            )

        aes = AESGCM(
            self.session_key
        )

        # AES-GCM recommends a unique 12-byte nonce
        nonce = os.urandom(12)

        encrypted = aes.encrypt(
            nonce,
            message.encode("utf-8"),
            None
        )

        return {
            "nonce": base64.b64encode(
                nonce
            ).decode("utf-8"),

            "ciphertext": base64.b64encode(
                encrypted
            ).decode("utf-8")
        }

    # ==========================================
    # DECRYPT MESSAGE
    # ==========================================

    def decrypt_message(
        self,
        nonce,
        ciphertext
    ):

        if self.session_key is None:
            raise Exception(
                "Secure session has not been established"
            )

        aes = AESGCM(
            self.session_key
        )

        nonce_bytes = base64.b64decode(
            nonce
        )

        ciphertext_bytes = base64.b64decode(
            ciphertext
        )

        decrypted = aes.decrypt(
            nonce_bytes,
            ciphertext_bytes,
            None
        )

        return decrypted.decode("utf-8")