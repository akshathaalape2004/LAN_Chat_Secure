import socket
import threading
import json
import time

from crypto_utils import SecureSession
from security import Identity
from file_transfer import register_session, unregister_session


# =========================================================
# CONFIGURATION
# =========================================================

DISCOVERY_PORTS = range(5001, 5011)


class LANChat:

    def __init__(self, username, on_message=None, on_user=None):

        self.username = username
        self.on_message = on_message
        self.on_user = on_user

        self.connections = {}
        self.peers = {}

        # Secure sessions for each user
        self.sessions = {}

        # Ed25519 identity
        self.identity = Identity(self.username)

        # Trusted Ed25519 public keys
        # First connection uses Trust-On-First-Use (TOFU).
        self.trusted_keys = {}

        print(
            f"{self.username} Ed25519 identity ready"
        )

        print(
            f"Ed25519 public key: "
            f"{self.identity.get_public_key()}"
        )

        # =================================================
        # TCP SERVER
        # =================================================

        self.server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        self.server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        # Keep localhost for current testing setup
        self.server_socket.bind(
            ("127.0.0.1", 0)
        )

        self.server_socket.listen(10)

        self.chat_port = (
            self.server_socket.getsockname()[1]
        )

        print(
            f"{self.username} chat server running on port "
            f"{self.chat_port}"
        )

        # =================================================
        # FIND UNIQUE DISCOVERY PORT
        # =================================================

        self.discovery_port = (
            self.find_discovery_port()
        )

        print(
            f"{self.username} discovery listener on port "
            f"{self.discovery_port}"
        )

        # =================================================
        # START THREADS
        # =================================================

        threading.Thread(
            target=self.accept_connections,
            daemon=True
        ).start()

        threading.Thread(
            target=self.discovery_listener,
            daemon=True
        ).start()

        threading.Thread(
            target=self.discovery_broadcaster,
            daemon=True
        ).start()

    # =====================================================
    # FIND AVAILABLE UDP PORT
    # =====================================================

    def find_discovery_port(self):

        for port in DISCOVERY_PORTS:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )

            try:

                sock.bind(
                    ("127.0.0.1", port)
                )

                sock.close()

                return port

            except OSError:

                sock.close()

        raise RuntimeError(
            "No discovery port available."
        )

    # =====================================================
    # SEND JSON PACKET
    # =====================================================

    def send_packet(self, sock, packet):

        data = json.dumps(packet) + "\n"

        sock.sendall(
            data.encode("utf-8")
        )

    # =====================================================
    # RECEIVE JSON PACKET
    # =====================================================

    def receive_packet(self, sock):

        data = b""

        while True:

            chunk = sock.recv(1)

            if not chunk:
                return None

            if chunk == b"\n":
                break

            data += chunk

        if not data:
            return None

        return json.loads(
            data.decode("utf-8")
        )

    # =====================================================
    # CREATE AUTHENTICATION MESSAGE
    # =====================================================

    def create_auth_message(
        self,
        username,
        x25519_public_key
    ):

        return json.dumps(
            {
                "username": username,
                "x25519_public_key": x25519_public_key
            },
            sort_keys=True
        )

    # =====================================================
    # VERIFY ED25519 IDENTITY
    # =====================================================

    def verify_peer_identity(
        self,
        username,
        identity_public_key,
        identity_signature,
        x25519_public_key
    ):

        if not identity_public_key:
            print(
                f"No Ed25519 identity key received "
                f"from {username}"
            )
            return False

        if not identity_signature:
            print(
                f"No Ed25519 signature received "
                f"from {username}"
            )
            return False

        # Create the exact message that the peer signed
        auth_message = self.create_auth_message(
            username,
            x25519_public_key
        )

        # =================================================
        # TRUST-ON-FIRST-USE
        # =================================================

        if username not in self.trusted_keys:

            self.trusted_keys[
                username
            ] = identity_public_key

            print(
                f"New Ed25519 identity registered "
                f"for {username}"
            )

        # =================================================
        # CHECK FOR KEY CHANGE
        # =================================================

        elif (
            self.trusted_keys[username]
            != identity_public_key
        ):

            print(
                "========================================"
            )

            print(
                f"SECURITY WARNING: Ed25519 public key "
                f"changed for {username}"
            )

            print(
                "Connection rejected."
            )

            print(
                "========================================"
            )

            return False

        # =================================================
        # VERIFY DIGITAL SIGNATURE
        # =================================================

        valid = Identity.verify(
            identity_public_key,
            identity_signature,
            auth_message
        )

        if valid:

            print(
                f"Ed25519 authentication SUCCESS "
                f"for {username}"
            )

            return True

        print(
            f"Ed25519 authentication FAILED "
            f"for {username}"
        )

        return False

    # =====================================================
    # TCP SERVER
    # =====================================================

    def accept_connections(self):

        while True:

            try:

                conn, address = (
                    self.server_socket.accept()
                )

                print(
                    f"Connection received from "
                    f"{address}"
                )

                threading.Thread(
                    target=self.handle_connection,
                    args=(conn, address),
                    daemon=True
                ).start()

            except Exception as e:

                print(
                    "Server error:",
                    e
                )

    # =====================================================
    # HANDLE CONNECTION
    # =====================================================

    def handle_connection(
        self,
        conn,
        address
    ):

        username = None

        try:

            while True:

                packet = self.receive_packet(
                    conn
                )

                if packet is None:
                    break

                packet_type = packet.get(
                    "type"
                )

                # =========================================
                # HELLO / AUTHENTICATED HANDSHAKE
                # =========================================

                if packet_type == "hello":

                    username = packet.get(
                        "username"
                    )

                    peer_port = packet.get(
                        "port"
                    )

                    # X25519 public key
                    peer_x25519_public_key = (
                        packet.get("public_key")
                    )

                    # Ed25519 public key
                    peer_identity_public_key = (
                        packet.get(
                            "identity_public_key"
                        )
                    )

                    # Ed25519 signature
                    peer_identity_signature = (
                        packet.get(
                            "identity_signature"
                        )
                    )

                    if not username:

                        print(
                            "Handshake rejected: "
                            "username missing"
                        )

                        conn.close()
                        return

                    if not peer_x25519_public_key:

                        print(
                            f"No X25519 public key "
                            f"received from {username}"
                        )

                        conn.close()
                        return

                    # =====================================
                    # VERIFY ED25519 AUTHENTICATION
                    # =====================================

                    authenticated = (
                        self.verify_peer_identity(
                            username,
                            peer_identity_public_key,
                            peer_identity_signature,
                            peer_x25519_public_key
                        )
                    )

                    if not authenticated:

                        print(
                            f"Rejected unauthenticated "
                            f"connection from {username}"
                        )

                        conn.close()
                        return

                    # =====================================
                    # CREATE X25519 SESSION
                    # =====================================

                    session = SecureSession()

                    session.generate_session_key(
                        peer_x25519_public_key
                    )

                    self.sessions[
                        username
                    ] = session

                    register_session(
                           username,
                           session.session_key
                   )

                    self.connections[
                        username
                    ] = conn

                    # =====================================
                    # SAVE PEER INFORMATION
                    # =====================================

                    if peer_port:

                        self.peers[
                            username
                        ] = {
                            "ip": address[0],
                            "port": peer_port
                        }

                    print(
                        f"Connection established with "
                        f"{username}"
                    )

                    print(
                        f"Secure session established with "
                        f"{username}"
                    )

                    # =====================================
                    # NOTIFY GUI
                    # =====================================

                    if self.on_user:

                        self.on_user(
                            username,
                            address[0]
                        )

                    # =====================================
                    # CREATE OUR X25519 PUBLIC KEY
                    # =====================================

                    my_x25519_public_key = (
                        session.get_public_key()
                    )

                    # =====================================
                    # SIGN OUR X25519 PUBLIC KEY
                    # WITH ED25519
                    # =====================================

                    auth_message = (
                        self.create_auth_message(
                            self.username,
                            my_x25519_public_key
                        )
                    )

                    identity_signature = (
                        self.identity.sign(
                            auth_message
                        )
                    )

                    # =====================================
                    # SEND HELLO ACK
                    # =====================================

                    self.send_packet(
                        conn,
                        {
                            "type": "hello_ack",

                            "username":
                                self.username,

                            "public_key":
                                my_x25519_public_key,

                            "identity_public_key":
                                self.identity.get_public_key(),

                            "identity_signature":
                                identity_signature
                        }
                    )

                    print(
                        f"Authenticated handshake completed "
                        f"with {username}"
                    )

                # =========================================
                # CHAT MESSAGE
                # =========================================

                elif packet_type == "chat":

                    sender = packet.get(
                        "username",
                        "Unknown"
                    )

                    nonce = packet.get(
                        "nonce"
                    )

                    ciphertext = packet.get(
                        "ciphertext"
                    )

                    session = self.sessions.get(
                        sender
                    )

                    if session is None:

                        print(
                            f"No secure session for "
                            f"{sender}"
                        )

                        continue

                    try:

                        # =================================
                        # DECRYPT AES-GCM MESSAGE
                        # =================================

                        text = (
                            session.decrypt_message(
                                nonce,
                                ciphertext
                            )
                        )

                        print(
                            f"Encrypted message received "
                            f"from {sender}"
                        )

                        print(
                            f"Decrypted message: {text}"
                        )

                        if self.on_message:

                            self.on_message(
                                sender,
                                text
                            )

                    except Exception as e:

                        print(
                            f"Message decryption failed: "
                            f"{e}"
                        )

        except Exception as e:

            print(
                "Connection error:",
                e
            )

        finally:

            if username:

                if (
                    self.connections.get(username)
                    == conn
                ):

                    del self.connections[
                        username
                    ]

                    self.sessions.pop(
                        username,
                        None
                    )
                    unregister_session(
                         username
                    )

            try:

                conn.close()

            except:

                pass

    # =====================================================
    # SEND MESSAGE
    # =====================================================

    def send_message(
        self,
        username,
        text
    ):

        # ================================================
        # CONNECT IF NECESSARY
        # ================================================

        if username not in self.connections:

            success = self.connect_to_peer(
                username
            )

            if not success:
                return False

        try:

            session = self.sessions.get(
                username
            )

            if session is None:

                print(
                    f"No secure session with "
                    f"{username}"
                )

                return False

            # ============================================
            # AES-256-GCM ENCRYPTION
            # ============================================

            encrypted = (
                session.encrypt_message(
                    text
                )
            )

            # ============================================
            # IMPORTANT:
            # PLAINTEXT IS NOT SENT
            # ============================================

            packet = {
                "type": "chat",

                "username":
                    self.username,

                "nonce":
                    encrypted["nonce"],

                "ciphertext":
                    encrypted["ciphertext"]
            }

            self.send_packet(
                self.connections[username],
                packet
            )

            print(
                f"Encrypted message sent to "
                f"{username}"
            )

            print(
                f"Ciphertext: "
                f"{encrypted['ciphertext']}"
            )

            return True

        except Exception as e:

            print(
                "Message sending error:",
                e
            )

            return False

    # =====================================================
    # CONNECT TO PEER
    # =====================================================

    def connect_to_peer(
        self,
        username
    ):

        if username not in self.peers:

            print(
                f"Peer {username} not found"
            )

            return False

        ip = self.peers[
            username
        ]["ip"]

        port = self.peers[
            username
        ]["port"]

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.connect(
                (ip, port)
            )

            # ============================================
            # CREATE X25519 SESSION
            # ============================================

            session = SecureSession()

            my_x25519_public_key = (
                session.get_public_key()
            )

            # ============================================
            # CREATE AUTHENTICATION MESSAGE
            # ============================================

            auth_message = (
                self.create_auth_message(
                    self.username,
                    my_x25519_public_key
                )
            )

            # ============================================
            # SIGN X25519 KEY WITH ED25519
            # ============================================

            identity_signature = (
                self.identity.sign(
                    auth_message
                )
            )

            # ============================================
            # SEND HELLO
            # ============================================

            self.send_packet(
                sock,
                {
                    "type": "hello",

                    "username":
                        self.username,

                    "port":
                        self.chat_port,

                    "public_key":
                        my_x25519_public_key,

                    "identity_public_key":
                        self.identity.get_public_key(),

                    "identity_signature":
                        identity_signature
                }
            )

            print(
                f"Authentication request sent "
                f"to {username}"
            )

            # ============================================
            # WAIT FOR HELLO ACK
            # ============================================

            response = self.receive_packet(
                sock
            )

            if response is None:

                print(
                    f"No handshake response from "
                    f"{username}"
                )

                sock.close()

                return False

            if response.get(
                "type"
            ) != "hello_ack":

                print(
                    f"Invalid handshake response "
                    f"from {username}"
                )

                sock.close()

                return False

            # ============================================
            # CHECK RESPONSE USERNAME
            # ============================================

            response_username = response.get(
                "username"
            )

            if response_username != username:

                print(
                    "SECURITY ERROR: Username mismatch"
                )

                sock.close()

                return False

            # ============================================
            # GET PEER X25519 KEY
            # ============================================

            peer_x25519_public_key = (
                response.get(
                    "public_key"
                )
            )

            # ============================================
            # GET PEER ED25519 KEY
            # ============================================

            peer_identity_public_key = (
                response.get(
                    "identity_public_key"
                )
            )

            peer_identity_signature = (
                response.get(
                    "identity_signature"
                )
            )

            if not peer_x25519_public_key:

                print(
                    f"No X25519 public key received "
                    f"from {username}"
                )

                sock.close()

                return False

            # ============================================
            # VERIFY PEER ED25519 SIGNATURE
            # ============================================

            authenticated = (
                self.verify_peer_identity(
                    username,
                    peer_identity_public_key,
                    peer_identity_signature,
                    peer_x25519_public_key
                )
            )

            if not authenticated:

                print(
                    f"SECURITY: Authentication failed "
                    f"for {username}"
                )

                sock.close()

                return False

            # ============================================
            # GENERATE SHARED X25519 SESSION KEY
            # ============================================

            session.generate_session_key(
                peer_x25519_public_key
            )

            self.sessions[
                username
            ] = session

            register_session(
                    username,
                    session.session_key
            )

            self.connections[
                username
            ] = sock

            print(
                f"Connected to {username}"
            )

            print(
                f"Ed25519 authentication SUCCESS "
                f"for {username}"
            )

            print(
                f"Secure session established with "
                f"{username}"
            )

            # ============================================
            # START RECEIVING THREAD
            # ============================================

            threading.Thread(
                target=self.handle_connection,
                args=(
                    sock,
                    (ip, port)
                ),
                daemon=True
            ).start()

            return True

        except Exception as e:

            print(
                f"Could not connect to "
                f"{username}: {e}"
            )

            return False

    # =====================================================
    # DISCOVERY LISTENER
    # =====================================================

    def discovery_listener(self):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        try:

            sock.bind(
                (
                    "127.0.0.1",
                    self.discovery_port
                )
            )

        except Exception as e:

            print(
                "Discovery listener error:",
                e
            )

            return

        while True:

            try:

                data, address = (
                    sock.recvfrom(2048)
                )

                packet = json.loads(
                    data.decode("utf-8")
                )

                if packet.get(
                    "type"
                ) != "discover":

                    continue

                username = packet.get(
                    "username"
                )

                if not username:
                    continue

                # Ignore ourselves
                if username == self.username:
                    continue

                ip = "127.0.0.1"

                port = packet.get(
                    "port"
                )

                if not port:
                    continue

                old_peer = self.peers.get(
                    username
                )

                new_peer = {
                    "ip": ip,
                    "port": port
                }

                self.peers[
                    username
                ] = new_peer

                # Notify GUI only when new/changed
                if old_peer != new_peer:

                    print(
                        f"Discovered {username} "
                        f"at {ip}:{port}"
                    )

                    if self.on_user:

                        self.on_user(
                            username,
                            ip
                        )

            except Exception as e:

                print(
                    "Discovery error:",
                    e
                )

    # =====================================================
    # DISCOVERY BROADCASTER
    # =====================================================

    def discovery_broadcaster(self):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        packet = json.dumps(
            {
                "type": "discover",
                "username": self.username,
                "port": self.chat_port
            }
        ).encode("utf-8")

        while True:

            try:

                # Send discovery packet to all
                # possible local discovery ports
                for port in DISCOVERY_PORTS:

                    try:

                        sock.sendto(
                            packet,
                            (
                                "127.0.0.1",
                                port
                            )
                        )

                    except:

                        pass

                time.sleep(3)

            except Exception as e:

                print(
                    "Discovery broadcast error:",
                    e
                )

                break