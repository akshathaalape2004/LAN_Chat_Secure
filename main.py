
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime
import threading
import os

from network import LANChat
from file_transfer import receive_file, send_file as transfer_file


# =========================================================
# THEME
# =========================================================

BG = "#111827"
SIDEBAR = "#1F2937"
PANEL = "#273449"
ACCENT = "#6366F1"
TEXT = "#F9FAFB"
MUTED = "#9CA3AF"
GREEN = "#22C55E"
BORDER = "#374151"


class LANChatApp:

    def __init__(self, root):
        self.root = root
        self.root.title("SecureConnect | LAN Messenger")
        self.root.geometry("1000x680")
        self.root.minsize(800, 550)
        self.root.configure(bg=BG)

        self.closing = False
        self.selected_user = None
        self.users = {}

        self.username = simpledialog.askstring(
            "Welcome",
            "Enter your username:",
            parent=root
        )

        if not self.username or not self.username.strip():
            self.username = "User"
        else:
            self.username = self.username.strip()

        self.build_ui()

        self.network = LANChat(
            self.username,
            on_message=self.receive_message,
            on_user=self.user_discovered
        )

        self.root.protocol("WM_DELETE_WINDOW", self.close_app)

    # =====================================================
    # UI
    # =====================================================

    def build_ui(self):

        header = tk.Frame(self.root, bg=SIDEBAR, height=75)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="SecureConnect",
            bg=SIDEBAR,
            fg=TEXT,
            font=("Segoe UI", 20, "bold")
        ).pack(side="left", padx=22, pady=16)

        tk.Label(
            header,
            text="LAN MESSENGER",
            bg=SIDEBAR,
            fg="#A5B4FC",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=8, pady=23)

        self.connection_status = tk.Label(
            header,
            text="● Application running",
            bg=SIDEBAR,
            fg=GREEN,
            font=("Segoe UI", 10)
        )
        self.connection_status.pack(side="right", padx=20)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=14, pady=14)

        # ---------------- Sidebar ----------------

        sidebar = tk.Frame(body, bg=SIDEBAR, width=245)
        sidebar.pack(side="left", fill="y", padx=(0, 14))
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="YOUR ACCOUNT",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", padx=18, pady=(20, 5))

        tk.Label(
            sidebar,
            text=f"●  {self.username}",
            bg=SIDEBAR,
            fg=TEXT,
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=18, pady=(0, 22))

        tk.Label(
            sidebar,
            text="ONLINE USERS",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", padx=18, pady=(0, 10))

        self.user_list = tk.Listbox(
            sidebar,
            bg=SIDEBAR,
            fg=TEXT,
            selectbackground=ACCENT,
            selectforeground="white",
            font=("Segoe UI", 11),
            borderwidth=0,
            highlightthickness=0,
            activestyle="none",
            exportselection=False
        )
        self.user_list.pack(
            fill="both", expand=True, padx=10, pady=(0, 10)
        )
        self.user_list.bind(
            "<<ListboxSelect>>", self.select_user
        )

        tk.Label(
            sidebar,
            text="Encrypted messaging\nand file sharing",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 9),
            justify="left"
        ).pack(anchor="w", padx=18, pady=16)

        # ---------------- Chat panel ----------------

        chat = tk.Frame(body, bg=BG)
        chat.pack(side="right", fill="both", expand=True)

        chat_header = tk.Frame(chat, bg=PANEL, height=68)
        chat_header.pack(fill="x")
        chat_header.pack_propagate(False)

        self.chat_title = tk.Label(
            chat_header,
            text="Choose a user to start chatting",
            bg=PANEL,
            fg=TEXT,
            font=("Segoe UI", 13, "bold")
        )
        self.chat_title.pack(side="left", padx=18, pady=18)

        # ---------------- Chat history ----------------

        history_frame = tk.Frame(chat, bg=BG)
        history_frame.pack(fill="both", expand=True, pady=12)

        scrollbar = ttk.Scrollbar(history_frame)
        scrollbar.pack(side="right", fill="y")

        self.chat_box = tk.Text(
            history_frame,
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 10),
            wrap="word",
            state="disabled",
            padx=14,
            pady=12,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            yscrollcommand=scrollbar.set
        )
        self.chat_box.pack(fill="both", expand=True)
        scrollbar.config(command=self.chat_box.yview)

        self.chat_box.tag_configure(
            "mine",
            foreground="#A5B4FC",
            font=("Segoe UI", 10, "bold")
        )
        self.chat_box.tag_configure(
            "theirs",
            foreground="#86EFAC",
            font=("Segoe UI", 10, "bold")
        )
        self.chat_box.tag_configure(
            "time",
            foreground=MUTED,
            font=("Segoe UI", 8)
        )
        self.chat_box.tag_configure(
            "system",
            foreground="#FBBF24",
            font=("Segoe UI", 9, "italic")
        )

        # ---------------- Message composer ----------------

        composer = tk.Frame(chat, bg=PANEL)
        composer.pack(fill="x", pady=(0, 4))

        self.message_entry = tk.Entry(
            composer,
            bg="#1F2937",
            fg=TEXT,
            insertbackground=TEXT,
            font=("Segoe UI", 11),
            relief="flat",
            borderwidth=0
        )
        self.message_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(12, 6),
            pady=12,
            ipady=9
        )
        self.message_entry.bind(
            "<Return>", lambda event: self.send_message()
        )

        tk.Button(
            composer,
            text="＋ File",
            command=self.send_file,
            bg="#374151",
            fg=TEXT,
            activebackground="#4B5563",
            activeforeground=TEXT,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
            padx=12,
            pady=10
        ).pack(side="left", padx=5, pady=10)

        tk.Button(
            composer,
            text="Send ➤",
            command=self.send_message,
            bg=ACCENT,
            fg="white",
            activebackground="#4F46E5",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
            padx=16,
            pady=10
        ).pack(side="right", padx=(5, 12), pady=10)

        # ---------------- Status bar ----------------

        self.status = tk.Label(
            self.root,
            text=f"  Signed in as {self.username}",
            bg=SIDEBAR,
            fg=MUTED,
            anchor="w",
            font=("Segoe UI", 9)
        )
        self.status.pack(fill="x", side="bottom", ipady=7)

    # =====================================================
    # USER DISCOVERY
    # =====================================================

    def user_discovered(self, username, ip):
        if self.closing or username == self.username:
            return

        self.users[username] = ip
        self.root.after(0, self.update_user_list)

    def update_user_list(self):
        if self.closing:
            return

        selected = self.selected_user
        sorted_users = sorted(self.users)

        self.user_list.delete(0, tk.END)

        for username in sorted_users:
            self.user_list.insert(tk.END, f"●  {username}")

        if selected:
            for index, username in enumerate(sorted_users):
                if username == selected:
                    self.user_list.selection_set(index)
                    break

    def select_user(self, event=None):
        selection = self.user_list.curselection()
        if not selection:
            return

        display_name = self.user_list.get(selection[0])
        username = display_name.replace("●  ", "", 1)

        self.selected_user = username
        self.chat_title.config(text=f"Chat with {username}")
        self.clear_chat()
        self.message_entry.focus_set()
        self.status.config(text=f"  Selected peer: {username}")

    # =====================================================
    # CHAT
    # =====================================================

    def send_message(self):
        if not self.selected_user:
            messagebox.showwarning(
                "Select a user",
                "Choose an online user before sending a message.",
                parent=self.root
            )
            return

        text = self.message_entry.get().strip()
        if not text:
            return

        success = self.network.send_message(self.selected_user, text)

        if success:
            self.add_message("You", text, mine=True)
            self.message_entry.delete(0, tk.END)
        else:
            messagebox.showerror(
                "Message failed",
                "Could not send the message. Check the peer connection.",
                parent=self.root
            )

    def receive_message(self, username, text):
        if self.closing:
            return

        self.root.after(
            0,
            lambda: self.add_message(username, text, mine=False)
            if not self.closing else None
        )

    def add_message(self, sender, text, mine=False):
        if self.closing:
            return

        self.chat_box.config(state="normal")

        timestamp = datetime.now().strftime("%H:%M")
        tag = "mine" if mine else "theirs"

        self.chat_box.insert(tk.END, f"{sender}  ", tag)
        self.chat_box.insert(tk.END, f"{timestamp}\n", "time")
        self.chat_box.insert(tk.END, f"{text}\n\n")

        self.chat_box.see(tk.END)
        self.chat_box.config(state="disabled")

    def add_system_message(self, text):
        if self.closing:
            return

        self.chat_box.config(state="normal")
        self.chat_box.insert(tk.END, f"{text}\n\n", "system")
        self.chat_box.see(tk.END)
        self.chat_box.config(state="disabled")

    def clear_chat(self):
        self.chat_box.config(state="normal")
        self.chat_box.delete("1.0", tk.END)
        self.chat_box.config(state="disabled")

    # =====================================================
    # INCOMING FILE APPROVAL
    # =====================================================

    def request_file_approval(self, sender, filename, file_size):
        """
        Called by the file receiver thread.
        Show the approval dialog on the Tkinter main thread.
        """

        if self.closing:
            return False

        decision = {"accepted": False}
        completed = threading.Event()

        def ask_user():
            try:
                if self.closing:
                    return

                size_mb = file_size / (1024 * 1024)

                decision["accepted"] = messagebox.askyesno(
                    "Incoming secure file",
                    f"{sender} wants to send you a file.\n\n"
                    f"Filename: {filename}\n"
                    f"Size: {size_mb:.2f} MB\n\n"
                    "Do you want to accept this file?",
                    parent=self.root
                )
            finally:
                completed.set()

        try:
            self.root.after(0, ask_user)
        except tk.TclError:
            return False

        # Do not wait indefinitely for a GUI response.
        if not completed.wait(125):
            return False

        return decision["accepted"]

    def file_received_notification(self, sender, filename, filepath):
        """Notify the user after successful verification and saving."""

        if self.closing:
            return

        def notify():
            if self.closing:
                return

            self.add_system_message(
                f"Verified file received from {sender}: {filename}"
            )
            self.status.config(text=f"  Received: {filename}")

            messagebox.showinfo(
                "Secure file received",
                f"File received and verified successfully.\n\n"
                f"From: {sender}\n"
                f"Filename: {filename}\n\n"
                f"Saved to:\n{os.path.abspath(filepath)}",
                parent=self.root
            )

        try:
            self.root.after(0, notify)
        except tk.TclError:
            pass

    # =====================================================
    # OUTGOING FILE TRANSFER
    # =====================================================

    def send_file(self):
        if not self.selected_user:
            messagebox.showwarning(
                "Select a user",
                "Choose a user before sending a file.",
                parent=self.root
            )
            return

        file_path = filedialog.askopenfilename(
            title="Choose a file to send",
            filetypes=[("All files", "*.*")]
        )

        if not file_path:
            return

        # Preserve the existing username-based port arrangement.
        if self.selected_user.lower() == "rahul":
            receiver_port = 5003
        elif self.selected_user.lower() == "akshatha":
            receiver_port = 5002
        else:
            receiver_port = 5004

        receiver_ip = self.users.get(self.selected_user)

        if not receiver_ip:
            messagebox.showerror(
                "Peer unavailable",
                "Could not find this user's address.",
                parent=self.root
            )
            return

        filename = os.path.basename(file_path)

        self.add_system_message(f"Preparing file: {filename}")
        self.status.config(text=f"  Sending {filename}...")

        threading.Thread(
            target=self._send_file_worker,
            args=(
                file_path,
                receiver_ip,
                receiver_port,
                self.selected_user,
                filename
            ),
            daemon=True
        ).start()

    def _send_file_worker(
        self,
        file_path,
        receiver_ip,
        receiver_port,
        receiver_username,
        filename
    ):
        try:
            # Establish a secure chat session if necessary.
            if receiver_username not in self.network.sessions:
                connected = self.network.connect_to_peer(receiver_username)

                if not connected:
                    raise ConnectionError(
                        "Could not establish a secure chat session."
                    )

            session = self.network.sessions.get(receiver_username)

            if session is None or session.session_key is None:
                raise ConnectionError(
                    "Secure session key is unavailable."
                )

            success = transfer_file(
                file_path,
                receiver_ip,
                receiver_port,
                self.username,
                receiver_username
            )

            if not success:
                raise RuntimeError(
                    "Transfer was rejected, failed, or could not be verified."
                )

            self.root.after(
                0,
                lambda: self._file_result(filename, True, None)
                if not self.closing else None
            )

        except Exception as exc:
            error_text = str(exc)

            try:
                self.root.after(
                    0,
                    lambda err=error_text: self._file_result(
                        filename, False, err
                    ) if not self.closing else None
                )
            except tk.TclError:
                pass

    def _file_result(self, filename, success, error):
        if self.closing:
            return

        if success:
            self.add_system_message(
                f"File sent and verified successfully: {filename}"
            )
            self.status.config(text=f"  Transfer verified: {filename}")

            messagebox.showinfo(
                "File transfer complete",
                f"{filename} was accepted, received, and verified.",
                parent=self.root
            )
        else:
            self.add_system_message(f"File transfer failed: {filename}")
            self.status.config(text="  File transfer failed")

            messagebox.showerror(
                "File transfer failed",
                error or "The recipient rejected the file or verification failed.",
                parent=self.root
            )

    # =====================================================
    # SHUTDOWN
    # =====================================================

    def close_app(self):
        self.closing = True

        try:
            self.root.destroy()
        except tk.TclError:
            pass


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = LANChatApp(root)

    # Preserve the existing receiver-port arrangement.
    if app.username.lower() == "akshatha":
        file_port = 5002
    elif app.username.lower() == "rahul":
        file_port = 5003
    else:
        file_port = 5004

    app.file_port = file_port

    threading.Thread(
        target=receive_file,
        args=(file_port,),
        kwargs={
            "on_file_request": app.request_file_approval,
            "on_file_received": app.file_received_notification
        },
        daemon=True
    ).start()

    root.mainloop()
