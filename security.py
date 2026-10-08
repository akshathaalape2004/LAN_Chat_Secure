import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class Identity:

    def __init__(self, username):
        self.username = username

        # Store one identity key per username
        safe_username = "".join(
            c if c.isalnum() or c in "_-" else "_"
            for c in username
        )

        self.identity_file = (
            f"identity_{safe_username}.json"
        )

        self.private_key = None
        self.public_key = None

        self.load_or_create_identity()

    # =====================================================
    # CREATE OR LOAD ED25519 IDENTITY
    # =====================================================

    def load_or_create_identity(self):

        if os.path.exists(self.identity_file):

            with open(
                self.identity_file,
                "r"
            ) as f:

                data = json.load(f)

            private_bytes = base64.b64decode(
                data["private_key"]
            )

            self.private_key = (
                ed25519.Ed25519PrivateKey
                .from_private_bytes(private_bytes)
            )

            self.public_key = (
                self.private_key.public_key()
            )

            print(
                f"Loaded existing identity for "
                f"{self.username}"
            )

        else:

            self.private_key = (
                ed25519.Ed25519PrivateKey.generate()
            )

            self.public_key = (
                self.private_key.public_key()
            )

            private_bytes = (
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=
                        serialization.NoEncryption()
                )
            )

            public_bytes = (
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )

            data = {
                "username": self.username,
                "private_key":
                    base64.b64encode(
                        private_bytes
                    ).decode("utf-8"),
                "public_key":
                    base64.b64encode(
                        public_bytes
                    ).decode("utf-8")
            }

            with open(
                self.identity_file,
                "w"
            ) as f:

                json.dump(
                    data,
                    f,
                    indent=4
                )

            print(
                f"Created new Ed25519 identity for "
                f"{self.username}"
            )

    # =====================================================
    # GET PUBLIC KEY
    # =====================================================

    def get_public_key(self):

        public_bytes = (
            self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

        return base64.b64encode(
            public_bytes
        ).decode("utf-8")

    # =====================================================
    # SIGN DATA
    # =====================================================

    def sign(self, data):

        if isinstance(data, str):
            data = data.encode("utf-8")

        signature = self.private_key.sign(
            data
        )

        return base64.b64encode(
            signature
        ).decode("utf-8")

    # =====================================================
    # VERIFY SIGNATURE
    # =====================================================

    @staticmethod
    def verify(
        public_key,
        signature,
        data
    ):

        try:

            public_bytes = base64.b64decode(
                public_key
            )

            signature_bytes = base64.b64decode(
                signature
            )

            public_key_object = (
                ed25519.Ed25519PublicKey
                .from_public_bytes(
                    public_bytes
                )
            )

            if isinstance(data, str):
                data = data.encode("utf-8")

            public_key_object.verify(
                signature_bytes,
                data
            )

            return True

        except (
            InvalidSignature,
            ValueError,
            TypeError
        ):

            return False