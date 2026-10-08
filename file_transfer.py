import socket
import os
import hashlib
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BUFFER_SIZE = 64 * 1024
NONCE_SIZE = 12
GCM_TAG_SIZE = 16

MAX_USERNAME_LENGTH = 256
MAX_FILENAME_LENGTH = 1024


# Stores the existing X25519/HKDF session keys.
# Key = peer username
_SESSION_KEYS = {}
_SESSION_LOCK = threading.Lock()


def register_session(username, session_key):
    """
    Register an already-established secure chat session
    for use by file transfer.
    """

    if not username:
        raise ValueError("Username is required")

    if not isinstance(session_key, bytes):
        raise TypeError("Session key must be bytes")

    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes")

    with _SESSION_LOCK:
        _SESSION_KEYS[username] = session_key

    print(
        f"Secure file-transfer session registered for {username}"
    )


def unregister_session(username):
    """
    Remove a session when the chat connection closes.
    """

    with _SESSION_LOCK:
        _SESSION_KEYS.pop(username, None)


def get_session_key(username):
    """
    Get the existing secure session key for a peer.
    """

    with _SESSION_LOCK:
        return _SESSION_KEYS.get(username)


def recv_exact(sock, length):
    """
    Receive exactly 'length' bytes.
    """

    data = b""

    while len(data) < length:

        chunk = sock.recv(
            length - len(data)
        )

        if not chunk:
            raise ConnectionError(
                "Connection closed while receiving data"
            )

        data += chunk

    return data


def send_uint32(sock, value):
    sock.sendall(
        value.to_bytes(
            4,
            byteorder="big"
        )
    )


def recv_uint32(sock):
    return int.from_bytes(
        recv_exact(sock, 4),
        byteorder="big"
    )


def send_uint64(sock, value):
    sock.sendall(
        value.to_bytes(
            8,
            byteorder="big"
        )
    )


def recv_uint64(sock):
    return int.from_bytes(
        recv_exact(sock, 8),
        byteorder="big"
    )


def build_aad(
    sender_username,
    filename,
    file_size,
    sha256_hash,
    chunk_number
):
    """
    Additional authenticated data for AES-GCM.

    This protects the file-transfer metadata and
    chunk ordering from tampering.
    """

    return (
        f"{sender_username}|"
        f"{filename}|"
        f"{file_size}|"
        f"{sha256_hash}|"
        f"{chunk_number}"
    ).encode("utf-8")


def receive_file(port):
    """
    Secure file receiver.

    File contents are encrypted using the existing
    X25519 + HKDF session key and AES-GCM.
    """

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        ("127.0.0.1", port)
    )

    server.listen(5)

    print(
        f"Secure file receiver listening on port {port}"
    )

    while True:

        conn = None

        try:

            conn, address = server.accept()

            print(
                f"File connection received from {address}"
            )

            # Protocol identifier
            magic = recv_exact(
                conn,
                5
            )

            if magic != b"LCSF1":

                print(
                    "Invalid file-transfer protocol."
                )

                conn.close()
                continue

            # -----------------------------
            # Receive sender username
            # -----------------------------

            username_length = recv_uint32(
                conn
            )

            if (
                username_length == 0
                or username_length > MAX_USERNAME_LENGTH
            ):

                raise ValueError(
                    "Invalid username length"
                )

            username_data = recv_exact(
                conn,
                username_length
            )

            sender_username = username_data.decode(
                "utf-8"
            )

            # -----------------------------
            # Receive filename
            # -----------------------------

            filename_length = recv_uint32(
                conn
            )

            if (
                filename_length == 0
                or filename_length > MAX_FILENAME_LENGTH
            ):

                raise ValueError(
                    "Invalid filename length"
                )

            filename_data = recv_exact(
                conn,
                filename_length
            )

            original_filename = filename_data.decode(
                "utf-8"
            )

            # Prevent path traversal
            filename = os.path.basename(
                original_filename
            )

            if not filename:
                raise ValueError(
                    "Invalid filename"
                )

            # -----------------------------
            # Receive file size
            # -----------------------------

            file_size = recv_uint64(
                conn
            )

            # -----------------------------
            # Receive expected SHA-256
            # -----------------------------

            expected_hash = recv_exact(
                conn,
                64
            ).decode("ascii")

            # -----------------------------
            # Find existing secure session
            # -----------------------------

            session_key = get_session_key(
                sender_username
            )

            if session_key is None:

                print(
                    f"No secure session exists for "
                    f"{sender_username}"
                )

                conn.close()
                continue

            aes = AESGCM(
                session_key
            )

            os.makedirs(
                "received_files",
                exist_ok=True
            )

            filepath = os.path.join(
                "received_files",
                filename
            )

            # Prevent accidental overwrite
            if os.path.exists(filepath):

                base, extension = os.path.splitext(
                    filename
                )

                counter = 1

                while os.path.exists(filepath):

                    filepath = os.path.join(
                        "received_files",
                        f"{base}_{counter}{extension}"
                    )

                    counter += 1

            temp_filepath = filepath + ".part"

            hasher = hashlib.sha256()

            received_size = 0
            chunk_number = 0

            print(
                f"Receiving encrypted file: {filename}"
            )

            with open(
                temp_filepath,
                "wb"
            ) as file:

                while received_size < file_size:

                    encrypted_length = recv_uint32(
                        conn
                    )

                    if encrypted_length < GCM_TAG_SIZE:

                        raise ValueError(
                            "Invalid encrypted chunk size"
                        )

                    if encrypted_length > (
                        BUFFER_SIZE + GCM_TAG_SIZE
                    ):

                        raise ValueError(
                            "Encrypted chunk is too large"
                        )

                    nonce = recv_exact(
                        conn,
                        NONCE_SIZE
                    )

                    encrypted_data = recv_exact(
                        conn,
                        encrypted_length
                    )

                    aad = build_aad(
                        sender_username,
                        filename,
                        file_size,
                        expected_hash,
                        chunk_number
                    )

                    plaintext = aes.decrypt(
                        nonce,
                        encrypted_data,
                        aad
                    )

                    remaining = (
                        file_size - received_size
                    )

                    if len(plaintext) > remaining:

                        raise ValueError(
                            "Received more data than expected"
                        )

                    file.write(
                        plaintext
                    )

                    hasher.update(
                        plaintext
                    )

                    received_size += len(
                        plaintext
                    )

                    chunk_number += 1

            # -----------------------------
            # Verify SHA-256
            # -----------------------------

            actual_hash = hasher.hexdigest()

            print(
                f"Expected SHA-256: {expected_hash}"
            )

            print(
                f"Actual SHA-256:   {actual_hash}"
            )

            if actual_hash != expected_hash:

                print(
                    "❌ FILE INTEGRITY VERIFICATION FAILED"
                )

                if os.path.exists(
                    temp_filepath
                ):
                    os.remove(
                        temp_filepath
                    )

                conn.close()
                continue

            os.replace(
                temp_filepath,
                filepath
            )

            print(
                "================================"
            )

            print(
                "✅ SECURE FILE RECEIVED"
            )

            print(
                f"File: {filepath}"
            )

            print(
                f"Size: {received_size} bytes"
            )

            print(
                "AES-GCM authentication: SUCCESS"
            )

            print(
                "SHA-256 integrity: SUCCESS"
            )

            print(
                "================================"
            )

            conn.close()

        except Exception as e:

            print(
                "Secure file receive error:",
                e
            )

            if conn is not None:

                try:
                    conn.close()
                except Exception:
                    pass


def send_file(
    file_path,
    receiver_ip,
    receiver_port,
    sender_username,
    receiver_username
):
    """
    Securely send a file using the existing
    authenticated X25519 session key.
    """

    try:

        # -----------------------------
        # Validate file
        # -----------------------------

        if not os.path.isfile(
            file_path
        ):

            print(
                "File does not exist."
            )

            return False

        # -----------------------------
        # Get existing secure session
        # -----------------------------

        session_key = get_session_key(
            receiver_username
        )

        if session_key is None:

            print(
                f"No secure session exists for "
                f"{receiver_username}"
            )

            print(
                "Establish the secure chat session first."
            )

            return False

        filename = os.path.basename(
            file_path
        )

        filename_bytes = filename.encode(
            "utf-8"
        )

        sender_bytes = sender_username.encode(
            "utf-8"
        )

        if len(sender_bytes) > MAX_USERNAME_LENGTH:
            print("Username is too long.")
            return False

        if len(filename_bytes) > MAX_FILENAME_LENGTH:
            print("Filename is too long.")
            return False

        # -----------------------------
        # Calculate SHA-256
        # -----------------------------

        hasher = hashlib.sha256()

        file_size = 0

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                data = file.read(
                    BUFFER_SIZE
                )

                if not data:
                    break

                hasher.update(
                    data
                )

                file_size += len(
                    data
                )

        sha256_hash = hasher.hexdigest()

        print(
            f"File size: {file_size} bytes"
        )

        print(
            f"SHA-256: {sha256_hash}"
        )

        # -----------------------------
        # Connect to receiver
        # -----------------------------

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        print(
            f"Connecting securely to "
            f"{receiver_ip}:{receiver_port}"
        )

        sock.connect(
            (
                receiver_ip,
                receiver_port
            )
        )

        # -----------------------------
        # Protocol header
        # -----------------------------

        sock.sendall(
            b"LCSF1"
        )

        # Sender username
        send_uint32(
            sock,
            len(sender_bytes)
        )

        sock.sendall(
            sender_bytes
        )

        # Filename
        send_uint32(
            sock,
            len(filename_bytes)
        )

        sock.sendall(
            filename_bytes
        )

        # File size
        send_uint64(
            sock,
            file_size
        )

        # SHA-256
        sock.sendall(
            sha256_hash.encode(
                "ascii"
            )
        )

        # -----------------------------
        # AES-GCM encryption
        # -----------------------------

        aes = AESGCM(
            session_key
        )

        chunk_number = 0

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                plaintext = file.read(
                    BUFFER_SIZE
                )

                if not plaintext:
                    break

                nonce = os.urandom(
                    NONCE_SIZE
                )

                aad = build_aad(
                    sender_username,
                    filename,
                    file_size,
                    sha256_hash,
                    chunk_number
                )

                encrypted_data = aes.encrypt(
                    nonce,
                    plaintext,
                    aad
                )

                # Encrypted chunk length
                send_uint32(
                    sock,
                    len(encrypted_data)
                )

                # Random AES-GCM nonce
                sock.sendall(
                    nonce
                )

                # Encrypted data + authentication tag
                sock.sendall(
                    encrypted_data
                )

                chunk_number += 1

        sock.close()

        print(
            "================================"
        )

        print(
            "✅ SECURE FILE SENT"
        )

        print(
            f"File: {filename}"
        )

        print(
            f"Size: {file_size} bytes"
        )

        print(
            "AES-GCM encryption: SUCCESS"
        )

        print(
            f"SHA-256: {sha256_hash}"
        )

        print(
            "================================"
        )

        return True

    except Exception as e:

        print(
            "Secure file sending error:",
            e
        )

        try:
            sock.close()
        except Exception:
            pass

        return False