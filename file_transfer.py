
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
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1 GB
CONNECT_TIMEOUT = 10
TRANSFER_TIMEOUT = 120
APPROVAL_TIMEOUT = 120

_SESSION_KEYS = {}
_SESSION_LOCK = threading.Lock()


def register_session(username, session_key):
    if not username:
        raise ValueError("Username is required")
    if not isinstance(session_key, bytes) or len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes")

    with _SESSION_LOCK:
        _SESSION_KEYS[username] = session_key

    print(f"Secure file-transfer session registered for {username}")


def unregister_session(username):
    with _SESSION_LOCK:
        _SESSION_KEYS.pop(username, None)


def get_session_key(username):
    with _SESSION_LOCK:
        return _SESSION_KEYS.get(username)


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed during transfer")
        data.extend(chunk)
    return bytes(data)


def send_uint32(sock, value):
    sock.sendall(value.to_bytes(4, "big"))


def recv_uint32(sock):
    return int.from_bytes(recv_exact(sock, 4), "big")


def send_uint64(sock, value):
    sock.sendall(value.to_bytes(8, "big"))


def recv_uint64(sock):
    return int.from_bytes(recv_exact(sock, 8), "big")


def build_aad(sender_username, filename, file_size, sha256_hash, chunk_number):
    return (
        f"{sender_username}|{filename}|{file_size}|"
        f"{sha256_hash}|{chunk_number}"
    ).encode("utf-8")


def receive_file(port, on_file_request=None, on_file_received=None, server_socket=None):
    """
    Listen for encrypted file transfers.

    on_file_request(sender, filename, size) must return True
    to accept a file, or False to reject it.
    """

    if server_socket is None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(5)
    else:
        server = server_socket

    print(f"Secure file receiver listening on port {port}")

    while True:
        conn = None
        temp_filepath = None

        try:
            conn, address = server.accept()
            conn.settimeout(TRANSFER_TIMEOUT)
            print(f"File connection received from {address}")

            if recv_exact(conn, 5) != b"LCSF1":
                raise ValueError("Invalid file-transfer protocol")

            username_length = recv_uint32(conn)
            if not 1 <= username_length <= MAX_USERNAME_LENGTH:
                raise ValueError("Invalid sender username length")

            sender = recv_exact(conn, username_length).decode("utf-8")

            filename_length = recv_uint32(conn)
            if not 1 <= filename_length <= MAX_FILENAME_LENGTH:
                raise ValueError("Invalid filename length")

            supplied_filename = recv_exact(conn, filename_length).decode("utf-8")
            filename = os.path.basename(supplied_filename)

            if not filename or filename in (".", ".."):
                raise ValueError("Invalid filename")

            file_size = recv_uint64(conn)
            if file_size > MAX_FILE_SIZE:
                conn.sendall(b"R")
                raise ValueError("File exceeds the 1 GB size limit")

            expected_hash = recv_exact(conn, 64).decode("ascii")
            if (
                len(expected_hash) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in expected_hash)
            ):
                conn.sendall(b"R")
                raise ValueError("Invalid SHA-256 metadata")

            session_key = get_session_key(sender)
            if session_key is None:
                conn.sendall(b"R")
                raise ConnectionError(
                    f"No secure session key is available for {sender}"
                )

            # Ask the GUI to obtain the recipient's decision.
            if on_file_request is None:
                accepted = True
            else:
                accepted = bool(on_file_request(sender, filename, file_size))

            conn.sendall(b"A" if accepted else b"R")

            if not accepted:
                print(f"File rejected by recipient: {filename}")
                continue

            aes = AESGCM(session_key)
            os.makedirs("received_files", exist_ok=True)

            filepath = os.path.join("received_files", filename)
            base, extension = os.path.splitext(filename)
            counter = 1

            while os.path.exists(filepath):
                filepath = os.path.join(
                    "received_files", f"{base}_{counter}{extension}"
                )
                counter += 1

            temp_filepath = filepath + ".part"
            hasher = hashlib.sha256()
            received_size = 0
            chunk_number = 0

            with open(temp_filepath, "wb") as output:
                while received_size < file_size:
                    encrypted_length = recv_uint32(conn)

                    if not GCM_TAG_SIZE <= encrypted_length <= BUFFER_SIZE + GCM_TAG_SIZE:
                        raise ValueError("Invalid encrypted chunk length")

                    nonce = recv_exact(conn, NONCE_SIZE)
                    encrypted_data = recv_exact(conn, encrypted_length)

                    aad = build_aad(
                        sender, filename, file_size, expected_hash, chunk_number
                    )
                    plaintext = aes.decrypt(nonce, encrypted_data, aad)

                    if not plaintext:
                        raise ValueError("Unexpected empty file chunk")

                    if received_size + len(plaintext) > file_size:
                        raise ValueError("Received more data than expected")

                    output.write(plaintext)
                    hasher.update(plaintext)
                    received_size += len(plaintext)
                    chunk_number += 1

            actual_hash = hasher.hexdigest()

            if received_size != file_size or actual_hash != expected_hash:
                raise ValueError("File size or SHA-256 verification failed")

            os.replace(temp_filepath, filepath)
            temp_filepath = None

            # Tell the sender the receiver verified and saved the file.
            conn.sendall(b"S")

            print("=" * 40)
            print(f"SECURE FILE RECEIVED: {filepath}")
            print(f"Size: {received_size} bytes")
            print("AES-GCM authentication: SUCCESS")
            print("SHA-256 integrity: SUCCESS")
            print("=" * 40)

            if on_file_received:
                try:
                    on_file_received(sender, filename, filepath)
                except Exception as callback_error:
                    print("Receive notification error:", callback_error)

        except Exception as exc:
            print("Secure file receive error:", exc)

            if conn is not None:
                try:
                    conn.sendall(b"F")
                except OSError:
                    pass

        finally:
            if temp_filepath and os.path.exists(temp_filepath):
                try:
                    os.remove(temp_filepath)
                except OSError:
                    pass

            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass


def send_file(file_path, receiver_ip, receiver_port,
              sender_username, receiver_username):
    """Send a file and wait for recipient approval and verification."""

    sock = None

    try:
        if not os.path.isfile(file_path):
            raise FileNotFoundError("Selected file does not exist")

        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            raise ValueError("File exceeds the 1 GB size limit")

        session_key = get_session_key(receiver_username)
        if session_key is None:
            raise ConnectionError(
                f"No secure session exists for {receiver_username}"
            )

        filename = os.path.basename(file_path)
        sender_bytes = sender_username.encode("utf-8")
        filename_bytes = filename.encode("utf-8")

        if not sender_bytes or len(sender_bytes) > MAX_USERNAME_LENGTH:
            raise ValueError("Invalid sender username length")
        if not filename_bytes or len(filename_bytes) > MAX_FILENAME_LENGTH:
            raise ValueError("Invalid filename length")

        hasher = hashlib.sha256()
        with open(file_path, "rb") as source:
            while True:
                block = source.read(BUFFER_SIZE)
                if not block:
                    break
                hasher.update(block)

        sha256_hash = hasher.hexdigest()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((receiver_ip, receiver_port))
        sock.settimeout(TRANSFER_TIMEOUT)

        sock.sendall(b"LCSF1")

        send_uint32(sock, len(sender_bytes))
        sock.sendall(sender_bytes)

        send_uint32(sock, len(filename_bytes))
        sock.sendall(filename_bytes)

        send_uint64(sock, file_size)
        sock.sendall(sha256_hash.encode("ascii"))

        # Wait for explicit recipient approval.
        decision = recv_exact(sock, 1)
        if decision != b"A":
            print("Recipient rejected the file or the request timed out.")
            return False

        aes = AESGCM(session_key)
        chunk_number = 0
        sent_size = 0

        with open(file_path, "rb") as source:
            while True:
                plaintext = source.read(BUFFER_SIZE)
                if not plaintext:
                    break

                nonce = os.urandom(NONCE_SIZE)
                aad = build_aad(
                    sender_username, filename, file_size,
                    sha256_hash, chunk_number
                )
                encrypted_data = aes.encrypt(nonce, plaintext, aad)

                send_uint32(sock, len(encrypted_data))
                sock.sendall(nonce)
                sock.sendall(encrypted_data)

                sent_size += len(plaintext)
                chunk_number += 1

        if sent_size != file_size:
            raise IOError("File changed while being sent; verification required")

        # Success only after receiver confirms the file was verified and saved.
        result = recv_exact(sock, 1)
        if result != b"S":
            raise IOError("Receiver could not verify or save the file")

        print(f"SECURE FILE VERIFIED BY RECEIVER: {filename}")
        print(f"Size: {file_size} bytes")
        print(f"SHA-256: {sha256_hash}")
        return True

    except Exception as exc:
        print("Secure file sending error:", exc)
        return False

    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
