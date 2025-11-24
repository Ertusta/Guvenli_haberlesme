import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import subprocess
import sys
import os
import socket
import json
import threading
from utils_des import encrypt_message, decrypt_message

SERVER_IP = "127.0.0.1"
PORT = 5000

# server.py'yi başlat
server_path = os.path.join(os.path.dirname(__file__), "server/server.py")
subprocess.Popen([sys.executable, server_path])

class SimpleChatUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")
        self.master.geometry("600x500")

        self.username = None
        self.image_path = None
        self.key = None
        self.sock = None
        self.listener_thread = None
        self.stop_event = threading.Event()

        # Register Frame
        self.register_frame = tk.Frame(master)
        tk.Label(self.register_frame, text="Register", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.register_frame, text="Username:").pack()
        self.entry_username = tk.Entry(self.register_frame)
        self.entry_username.pack()

        tk.Button(self.register_frame, text="Select Image", command=self.select_image).pack(pady=5)
        tk.Button(self.register_frame, text="Register & Connect", command=self.register_and_connect).pack(pady=10)

        self.register_frame.pack(fill="both", expand=True)

        # Chat Frame
        self.chat_frame = tk.Frame(master)
        tk.Label(self.chat_frame, text="Chat", font=("Arial", 16)).pack(pady=10)

        self.text_area = tk.Text(self.chat_frame, state='disabled', height=20) 
        self.text_area.pack(pady=5, fill="both", expand=True)

# Receiver
        tk.Label(self.chat_frame, text="Receiver:").pack()
        self.entry_receiver = tk.Entry(self.chat_frame)
        self.entry_receiver.pack(fill="x", padx=5)

# Message ve Send butonu aynı satırda
        message_frame = tk.Frame(self.chat_frame)
        message_frame.pack(fill="x", pady=5, padx=5)

        self.entry_message = tk.Entry(message_frame)
        self.entry_message.pack(side="left", fill="x", expand=True)

        tk.Button(message_frame, text="Send", command=self.send_message).pack(side="left", padx=5)


    def select_image(self):
        self.image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("PNG Images", "*.png")])
        if self.image_path:
            if not hasattr(self, "label_image"):
                self.label_image = tk.Label(self.register_frame, text="")
                self.label_image.pack()
            self.label_image.config(text=os.path.basename(self.image_path))

    def register_and_connect(self):
        self.username = self.entry_username.get().strip()
 		
 	"""
 	////////////////////////////////////////////////////////////////	
 	"""
        self.key = "12345678"
        if not self.key:
            messagebox.showerror("Error", "Encryption key required")
            return
        if len(self.key) < 8:
            self.key = self.key.ljust(8, '0')
        elif len(self.key) > 8:
            self.key = self.key[:8]

	"""
 	////////////////////////////////////////////////////////////////	
 	"""
 	
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_IP, PORT))
        except Exception as e:
            messagebox.showerror("Connection Error", f"Cannot connect to server: {e}")
            return

        register_data = json.dumps({
            "type": "register",
            "username": self.username,
            "key": self.key
        }).encode()

        try:
            self.sock.send(register_data)
            response = self.sock.recv(4096)
            confirm = json.loads(response.decode())
            if confirm.get("status") == "registered":
                self.register_frame.pack_forget()
                self.chat_frame.pack(fill="both", expand=True)
                self.append_text("✅ Connected and registered successfully!\n")
                self.stop_event.clear()
                self.listener_thread = threading.Thread(target=self.listen_server, daemon=True)
                self.listener_thread.start()
            else:
                messagebox.showerror("Registration Failed", confirm.get("message", "Unknown error"))
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {e}")
            self.sock.close()
            self.sock = None

    def listen_server(self):
        while not self.stop_event.is_set():
            try:
                self.sock.settimeout(1.0)
                data = self.sock.recv(4096)
                if not data:
                    self.append_text("❌ Server disconnected\n")
                    break
                message = json.loads(data.decode())
                if message.get("type") == "message":
                    sender = message.get("sender")
                    encrypted = message.get("data")
                    decrypted = decrypt_message(self.key, encrypted)
                    self.append_text(f"📩 {sender}: {decrypted}\n")
            except socket.timeout:
                continue
            except Exception as e:
                self.append_text(f"⚠️ Error receiving message: {e}\n")
                break

    def send_message(self):
        if not self.sock:
            messagebox.showerror("Error", "Not connected to server")
            return
        receiver = self.entry_receiver.get().strip()
        message = self.entry_message.get().strip()
        if not receiver or not message:
            messagebox.showwarning("Warning", "Receiver and message cannot be empty")
            return
        try:
            encrypted = encrypt_message(self.key, message)
            msg_data = json.dumps({
                "type": "message",
                "sender": self.username,
                "receiver": receiver,
                "data": encrypted
            }).encode()
            self.sock.send(msg_data)
            self.append_text(f"✅ To {receiver}: {message}\n")
            self.entry_message.delete(0, tk.END)
        except Exception as e:
            self.append_text(f"❌ Failed to send message: {e}\n")

    def append_text(self, text):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, text)
        self.text_area.see(tk.END)
        self.text_area.config(state='disabled')

    def close(self):
        self.stop_event.set()
        if self.sock:
            self.sock.close()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleChatUI(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()
