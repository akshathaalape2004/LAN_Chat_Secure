import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from network import LANChat
from file_transfer import receive_file
import threading
import os


class LANChatApp:

    def __init__(self, root):
        self.root = root
        self.root.title("LAN Chat - Secure File Sharing")
        self.root.geometry("800x550")

        # Ask username
        self.username = simpledialog.askstring(
            "LAN Chat",
            "Enter your username:",
            parent=self.root
        )

        if not self.username:
            self.username = "User"

        # Variables
        self.selected_user = None
        self.users = {}

        # Create GUI
        self.create_gui()

        # Start network
        self.network = LANChat(
            self.username,
            on_message=self.receive_message,
            on_user=self.user_discovered
        )

    # =====================================================
    # GUI
    # =====================================================

    def create_gui(self):

        title = tk.Label(
            self.root,
            text="LAN CHAT APPLICATION",
            font=("Arial", 20, "bold")
        )
        title.pack(pady=10)

        main_frame = tk.Frame(self.root)
        main_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        # =================================================
        # USERS
        # =================================================

        users_frame = tk.Frame(
            main_frame,
            width=200,
            relief=tk.GROOVE,
            borderwidth=2
        )

        users_frame.pack(
            side="left",
            fill="y",
            padx=(0, 10)
        )

        tk.Label(
            users_frame,
            text="Online Users",
            font=("Arial", 13, "bold")
        ).pack(pady=10)

        self.user_list = tk.Listbox(
            users_frame,
            width=22,
            height=20,
            font=("Arial", 11)
        )

        self.user_list.pack(
            padx=10,
            pady=10
        )

        self.user_list.bind(
            "<<ListboxSelect>>",
            self.select_user
        )

        # =================================================
        # CHAT
        # =================================================

        chat_frame = tk.Frame(main_frame)

        chat_frame.pack(
            side="right",
            fill="both",
            expand=True
        )

        self.chat_title = tk.Label(
            chat_frame,
            text="Select a user to start chatting",
            font=("Arial", 13, "bold")
        )

        self.chat_title.pack(pady=5)

        self.chat_box = tk.Text(
            chat_frame,
            state="disabled",
            font=("Arial", 11),
            wrap="word"
        )

        self.chat_box.pack(
            fill="both",
            expand=True,
            padx=5,
            pady=5
        )

        # =================================================
        # MESSAGE ENTRY
        # =================================================

        message_frame = tk.Frame(chat_frame)
        message_frame.pack(
            fill="x",
            pady=5
        )

        self.message_entry = tk.Entry(
            message_frame,
            font=("Arial", 11)
        )

        self.message_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5
        )

        self.message_entry.bind(
            "<Return>",
            lambda event: self.send_message()
        )

        send_button = tk.Button(
            message_frame,
            text="SEND",
            width=10,
            command=self.send_message
        )

        send_button.pack(
            side="right",
            padx=5
        )

        # =================================================
        # FILE BUTTON
        # =================================================

        file_button = tk.Button(
            chat_frame,
            text="📎 Send File",
            command=self.send_file
        )

        file_button.pack(pady=5)

        # =================================================
        # STATUS
        # =================================================

        self.status = tk.Label(
            self.root,
            text=f"Logged in as: {self.username}",
            anchor="w"
        )

        self.status.pack(
            fill="x",
            padx=10,
            pady=5
        )

    # =====================================================
    # USER DISCOVERY
    # =====================================================

    def user_discovered(self, username, ip):

        if username == self.username:
            return

        self.users[username] = ip

        self.root.after(
            0,
            self.update_user_list
        )

    # =====================================================
    # UPDATE USER LIST
    # =====================================================

    def update_user_list(self):

        current_users = self.user_list.get(
            0,
            tk.END
        )

        for username in self.users:

            if username not in current_users:

                self.user_list.insert(
                    tk.END,
                    username
                )

    # =====================================================
    # SELECT USER
    # =====================================================

    def select_user(self, event=None):

        selection = self.user_list.curselection()

        if not selection:
            return

        self.selected_user = self.user_list.get(
            selection[0]
        )

        self.chat_title.config(
            text=f"Chat with {self.selected_user}"
        )

        self.clear_chat()

        self.message_entry.focus_set()

    # =====================================================
    # SEND MESSAGE
    # =====================================================

    def send_message(self):

        if not self.selected_user:

            messagebox.showwarning(
                "No User Selected",
                "Please select a user first."
            )

            return

        text = self.message_entry.get().strip()

        if not text:
            return

        success = self.network.send_message(
            self.selected_user,
            text
        )

        if success:

            self.add_message(
                f"You: {text}"
            )

            self.message_entry.delete(
                0,
                tk.END
            )

        else:

            messagebox.showerror(
                "Error",
                "Unable to send message."
            )

    # =====================================================
    # RECEIVE MESSAGE
    # =====================================================

    def receive_message(self, username, text):

        self.root.after(
            0,
            lambda: self.add_message(
                f"{username}: {text}"
            )
        )

    # =====================================================
    # DISPLAY MESSAGE
    # =====================================================

    def add_message(self, message):

        self.chat_box.config(
            state="normal"
        )

        self.chat_box.insert(
            tk.END,
            message + "\n"
        )

        self.chat_box.see(
            tk.END
        )

        self.chat_box.config(
            state="disabled"
        )

    # =====================================================
    # CLEAR CHAT
    # =====================================================

    def clear_chat(self):

        self.chat_box.config(
            state="normal"
        )

        self.chat_box.delete(
            "1.0",
            tk.END
        )

        self.chat_box.config(
            state="disabled"
        )

    # =====================================================
    # SEND FILE
    # =====================================================

         # =====================================================
    # SEND FILE
    # =====================================================

    def send_file(self):

        if not self.selected_user:
            messagebox.showwarning(
                "No User Selected",
                "Select a user before sending a file."
            )
            return

        file_path = filedialog.askopenfilename()

        if not file_path:
            return

        receiver_ip = self.users.get(
            self.selected_user
        )

        if not receiver_ip:
            messagebox.showerror(
                "Error",
                "Could not find the user's IP address."
            )
            return

        try:

            # Make sure a secure session exists
            if self.selected_user not in self.network.sessions:

                print(
                    f"No secure session with {self.selected_user}"
                )

                print(
                    "Establishing secure session..."
                )

                connected = self.network.connect_to_peer(
                    self.selected_user
                )

                if not connected:
                    messagebox.showerror(
                        "Secure Connection Error",
                        "Could not establish a secure session."
                    )
                    return

            # Check session
            session = self.network.sessions.get(
                self.selected_user
            )

            if session is None:
                messagebox.showerror(
                    "Security Error",
                    "Secure session is not available."
                )
                return

            if session.session_key is None:
                messagebox.showerror(
                    "Security Error",
                    "Encryption session key is not available."
                )
                return

            # Import secure file transfer
            from file_transfer import send_file as transfer_file

            filename = os.path.basename(file_path)

            self.add_message(
                f"📎 Encrypting and sending: {filename}"
            )

            print("================================")
            print("Secure file transfer")
            print(f"Sender: {self.username}")
            print(f"Receiver: {self.selected_user}")
            print(f"File: {filename}")
            print("================================")

            # Receiver file port
            if self.selected_user.lower() == "rahul":
                receiver_port = 5003

            elif self.selected_user.lower() == "akshatha":
                receiver_port = 5002

            else:
                receiver_port = 5004

            # Send encrypted file
            success = transfer_file(
                file_path,
                receiver_ip,
                receiver_port,
                self.username,
                self.selected_user
            )

            if success:

                self.add_message(
                    f"🔐 Secure file sent: {filename}"
                )

                messagebox.showinfo(
                    "Secure File Transfer",
                    "File encrypted and sent successfully!"
                )

            else:

                self.add_message(
                    f"❌ Secure file transfer failed: {filename}"
                )

                messagebox.showerror(
                    "File Transfer",
                    "Secure file transfer failed."
                )

        except Exception as e:

            print(
                "Secure file transfer error:",
                e
            )

            self.add_message(
                "❌ Secure file transfer failed"
            )

            messagebox.showerror(
                "File Transfer Error",
                str(e)
            )

# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = LANChatApp(root)

    # -----------------------------------------
    # Assign file receiving port
    # -----------------------------------------

    if app.username.lower() == "akshatha":

        file_port = 5002

    elif app.username.lower() == "rahul":

        file_port = 5003

    else:

        file_port = 5004

    app.file_port = file_port

    print(
        f"{app.username} file receiver will use port {file_port}"
    )

    # -----------------------------------------
    # Start file receiver
    # -----------------------------------------

    threading.Thread(
        target=receive_file,
        args=(file_port,),
        daemon=True
    ).start()

    # -----------------------------------------
    # Start GUI
    # -----------------------------------------

    root.mainloop()