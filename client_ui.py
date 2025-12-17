import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import json
import threading
import time
import base64
import os
from utils_des import encrypt_message, decrypt_message, embed_password_in_image

SERVER_IP = "127.0.0.1"
PORT = 5000

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

        # Login/Register Frame
        self.auth_frame = tk.Frame(master)
        
        # Title
        tk.Label(self.auth_frame, text="Secure Chat", font=("Arial", 18, "bold")).pack(pady=10)
        
        # Tab buttons
        button_frame = tk.Frame(self.auth_frame)
        button_frame.pack(pady=5)
        
        self.login_btn = tk.Button(button_frame, text="Login", command=self.show_login, bg="#4CAF50", fg="white", padx=20)
        self.login_btn.pack(side=tk.LEFT, padx=5)
        
        self.register_btn = tk.Button(button_frame, text="Register", command=self.show_register, bg="#2196F3", fg="white", padx=20)
        self.register_btn.pack(side=tk.LEFT, padx=5)
        
        # Login Frame (default)
        self.login_frame = tk.Frame(self.auth_frame)
        tk.Label(self.login_frame, text="Login", font=("Arial", 14)).pack(pady=10)
        
        tk.Label(self.login_frame, text="Username:").pack()
        self.entry_login_username = tk.Entry(self.login_frame)
        self.entry_login_username.pack(pady=5)
        
        tk.Label(self.login_frame, text="Password:").pack()
        self.entry_login_password = tk.Entry(self.login_frame, show="*")
        self.entry_login_password.pack(pady=5)
        
        tk.Button(self.login_frame, text="Login & Connect", command=self.login_and_connect, bg="#4CAF50", fg="white").pack(pady=10)
        
        # Register Frame (initially hidden)
        self.register_frame = tk.Frame(self.auth_frame)
        tk.Label(self.register_frame, text="Register", font=("Arial", 14)).pack(pady=10)
        
        tk.Label(self.register_frame, text="Username:").pack()
        self.entry_register_username = tk.Entry(self.register_frame)
        self.entry_register_username.pack(pady=5)
        
        tk.Label(self.register_frame, text="Password:").pack()
        self.entry_register_password = tk.Entry(self.register_frame, show="*")
        self.entry_register_password.pack(pady=5)

        tk.Button(self.register_frame, text="Select Image", command=self.select_image, bg="#FF9800", fg="white").pack(pady=5)
        self.register_image_label = tk.Label(self.register_frame, text="No image selected", fg="red")
        self.register_image_label.pack()
        
        tk.Button(self.register_frame, text="Register & Connect", command=self.register_and_connect, bg="#2196F3", fg="white").pack(pady=10)

        # Show login frame by default
        self.login_frame.pack(fill="both", expand=True)
        self.auth_frame.pack(fill="both", expand=True)

        # Main chat container (initially hidden)
        self.main_container = tk.PanedWindow(master, orient=tk.HORIZONTAL)
        
        # Left panel for active users
        self.left_panel = tk.Frame(self.main_container, width=150, bg='#f0f0f0')
        
        # Right panel for chat
        self.chat_frame = tk.Frame(self.main_container)
        
        # Initially hide the chat interface
        self.main_container.pack_forget()
        
        # Store active users and message history
        self.active_users = set()
        self.message_history = []
        self.current_chat_user = None


    def show_login(self):
        """Switch to login frame"""
        self.register_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.login_btn.config(bg="#4CAF50")
        self.register_btn.config(bg="#2196F3")

    def show_register(self):
        """Switch to register frame"""
        self.login_frame.pack_forget()
        self.register_frame.pack(fill="both", expand=True)
        self.register_btn.config(bg="#4CAF50")
        self.login_btn.config(bg="#2196F3")

    def select_image(self):
        """Kullanıcı resim seçer"""
        self.image_path = filedialog.askopenfilename(
            title="Select Image", 
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if self.image_path:
            self.register_image_label.config(text=f"✓ {os.path.basename(self.image_path)}", fg="green")
        else:
            self.register_image_label.config(text="No image selected", fg="red")

    def setup_chat_interface(self):
        """Set up the chat interface after successful login"""
        # Clear any existing widgets in the panels
        for widget in self.left_panel.winfo_children():
            widget.destroy()
        for widget in self.chat_frame.winfo_children():
            widget.destroy()
            
        # Active users list
        tk.Label(self.left_panel, text="Active Users", font=("Arial", 12, "bold"), bg='#f0f0f0').pack(pady=5)
        self.users_listbox = tk.Listbox(self.left_panel, selectmode=tk.SINGLE, height=20)
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        # Add panels to container
        self.main_container.add(self.left_panel, stretch='always')
        self.main_container.add(self.chat_frame, stretch='always')
        
        # Chat area with scrollbar
        self.text_frame = tk.Frame(self.chat_frame)
        self.text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = tk.Scrollbar(self.text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.text_area = tk.Text(self.text_frame, state='disabled', height=20, yscrollcommand=scrollbar.set)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.text_area.yview)
        
        # Message history button
        tk.Button(self.chat_frame, text="Load Message History", 
                 command=self.load_message_history).pack(fill=tk.X, padx=5, pady=2)
        
        # Receiver and message input
        receiver_frame = tk.Frame(self.chat_frame)
        receiver_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(receiver_frame, text="To:").pack(side=tk.LEFT)
        self.entry_receiver = tk.Entry(receiver_frame)
        self.entry_receiver.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Message input and send button
        message_frame = tk.Frame(self.chat_frame)
        message_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.entry_message = tk.Entry(message_frame)
        self.entry_message.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry_message.bind('<Return>', lambda e: self.send_message())
        
        send_btn = tk.Button(message_frame, text="Send", command=self.send_message)
        send_btn.pack(side=tk.LEFT, padx=5)
        
        # Show the main container
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
    def login_and_connect(self):
        self.username = self.entry_login_username.get().strip()
        self.key = self.entry_login_password.get().strip()
        
        if not self.username:
            messagebox.showerror("Error", "Username is required")
            return
            
        if not self.key:
            messagebox.showerror("Error", "Password is required")
            return
            
        # Ensure key is 8 bytes
        if len(self.key) < 8:
            self.key = self.key.ljust(8, '0')
        elif len(self.key) > 8:
            self.key = self.key[:8]
        
        self.connect_to_server("login")

    def register_and_connect(self):
        """REGISTER: Parolayı resme göm ve sunucuya gönder"""
        self.username = self.entry_register_username.get().strip()
        self.key = self.entry_register_password.get().strip()
        
        if not self.username:
            messagebox.showerror("Error", "Username is required")
            return
        
        if not self.key:
            messagebox.showerror("Error", "Password is required")
            return
        
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image!")
            return
            
        # Ensure key is 8 bytes
        if len(self.key) < 8:
            self.key = self.key.ljust(8, '0')
        elif len(self.key) > 8:
            self.key = self.key[:8]
        
        try:
            # 🔐 STEGANOGRAPHY: Parolayı resme göm
            temp_dir = os.path.join(os.path.dirname(__file__), "temp_images")
            os.makedirs(temp_dir, exist_ok=True)
            stego_image_path = os.path.join(temp_dir, f"{self.username}_stego.png")
            
            embed_password_in_image(self.image_path, self.key, stego_image_path)
            print(f"[CLIENT] ✅ Parola resme gömüldü: {stego_image_path}")
            
            # Resmi base64'e çevir
            with open(stego_image_path, 'rb') as f:
                image_data = base64.b64encode(f.read()).decode('utf-8')
            
            # Geçici dosyayı sil
            os.remove(stego_image_path)
            
        except Exception as e:
            messagebox.showerror("Error", f"Image processing failed: {e}")
            return
        
        # Sunucuya bağlan ve resmi gönder
        self.connect_to_server("register", image_data)

    def connect_to_server(self, action, image_data=None):
        """Shared connection logic for login/register"""
        # Close any existing socket to ensure a clean connection
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        
        # Kısa bir bekleme süresi ekle
        time.sleep(0.2)
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)  # Bağlantı için timeout
            self.sock.connect((SERVER_IP, PORT))
            self.sock.settimeout(1.0)  # Normal işlemler için timeout
        except socket.timeout:
            messagebox.showerror("Connection Error", "Sunucuya bağlanırken zaman aşımı! Server çalışıyor mu?")
            self.sock = None
            return
        except Exception as e:
            messagebox.showerror("Connection Error", f"Sunucuya bağlanılamadı: {e}")
            self.sock = None
            return

        payload = {
            "type": action,
            "username": self.username
        }
        
        # Register ise resim verisini ekle
        if action == "register":
            payload["image_data"] = image_data
        else:
            # Login ise sadece key gönder
            payload["key"] = self.key

        try:
            self.sock.send(json.dumps(payload).encode())
            response = self.sock.recv(8192)  # Büyük resim için 8KB
            confirm = json.loads(response.decode())
        except socket.timeout:
            messagebox.showerror("Error", f"{action.capitalize()} işlemi zaman aşımına uğradı")
            self.cleanup_socket()
            return
        except Exception as e:
            messagebox.showerror("Error", f"{action.capitalize()} işlemi başarısız: {e}")
            self.cleanup_socket()
            return

        status = confirm.get("status")
        success = (action == "register" and status == "registered") or (action == "login" and status == "login_success")

        if success:
            self.auth_frame.pack_forget()
            self.setup_chat_interface()
            success_msg = "✅ Connected and registered successfully!\n" if action == "register" else "✅ Logged in successfully!\n"
            self.append_text(success_msg)
            self.stop_event.clear()
            self.listener_thread = threading.Thread(target=self.listen_server, daemon=True)
            self.listener_thread.start()
            # Request initial user list
            try:
                self.sock.send(json.dumps({"type": "get_users"}).encode())
            except Exception as e:
                self.append_text(f"⚠️ Failed to fetch users: {e}\n")
        else:
            message = confirm.get("message", "Unknown error")
            title = "Registration Failed" if action == "register" else "Login Failed"
            messagebox.showerror(title, message)
            self.cleanup_socket()

    def cleanup_socket(self):
        """Güvenli socket temizleme"""
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def listen_server(self):
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    self.append_text("❌ Server disconnected\n")
                    break
                    
                message = json.loads(data.decode())
                msg_type = message.get("type")
                
                if msg_type == "message":
                    sender = message.get("from")
                    encrypted = message.get("data")
                    try:
                        decrypted = decrypt_message(self.key, encrypted)
                        self.append_text(f"📩 {sender}: {decrypted}\n")
                        # Add to message history
                        self.message_history.append({
                            'sender': sender,
                            'receiver': self.username,
                            'message': decrypted,
                            'timestamp': message.get('timestamp', '')
                        })
                    except Exception as e:
                        self.append_text(f"⚠️ Error decrypting message: {e}\n")
                        
                elif msg_type == "user_list":
                    # Update active users list
                    users = message.get("users", [])
                    self.update_user_list(users)
                    
                elif msg_type == "message_history":
                    # Display message history
                    history = message.get("messages", [])
                    self.display_message_history(history)
                    
            except socket.timeout:
                # Request updated user list periodically
                if self.sock and not self.stop_event.is_set():
                    try:
                        self.sock.send(json.dumps({"type": "get_users"}).encode())
                    except:
                        pass
                continue
                
            except json.JSONDecodeError:
                self.append_text("⚠️ Invalid message format from server\n")
                
            except Exception as e:
                if not self.stop_event.is_set():
                    self.append_text(f"⚠️ Error: {e}\n")
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
            msg_data = {
                "type": "message",
                "sender": self.username,
                "receiver": receiver,
                "data": encrypted
            }
            self.sock.send(json.dumps(msg_data).encode())
            
            # Add to message history
            self.message_history.append({
                'sender': self.username,
                'receiver': receiver,
                'message': message,
                'timestamp': ''  # Server will add timestamp
            })
            
            self.append_text(f"✅ To {receiver}: {message}\n")
            self.entry_message.delete(0, tk.END)
            
        except Exception as e:
            self.append_text(f"❌ Failed to send message: {e}\n")
    
    def update_user_list(self, users):
        """Update the list of active users in the UI"""
        current_users = set(users)
        
        # Update our internal set
        self.active_users = current_users
        
        # Update the listbox
        self.users_listbox.delete(0, tk.END)
        for user in sorted(users):
            if user != self.username:  # Don't show ourselves in the list
                self.users_listbox.insert(tk.END, user)
    
    def on_user_select(self, event):
        """When a user is selected from the list, set them as the message receiver"""
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            username = event.widget.get(index)
            self.entry_receiver.delete(0, tk.END)
            self.entry_receiver.insert(0, username)
    
    def load_message_history(self):
        """Request message history from the server"""
        if not self.sock:
            self.append_text("⚠️ Not connected to server\n")
            return
            
        receiver = self.entry_receiver.get().strip()
        if not receiver:
            messagebox.showwarning("Warning", "Lütfen önce bir kullanıcı seçin")
            return
            
        try:
            self.append_text("⏳ Mesaj geçmişi yükleniyor...\n")
            self.sock.send(json.dumps({
                "type": "get_history",
                "with_user": receiver
            }).encode())
            self.current_chat_user = receiver
        except Exception as e:
            self.append_text(f"⚠️ Mesaj geçmişi yüklenirken hata oluştu: {e}\n")
    
    def display_message_history(self, messages):
        """Display message history in the chat area"""
        self.text_area.config(state='normal')
        self.text_area.delete(1.0, tk.END)
        
        if not messages:
            self.text_area.insert(tk.END, "Mesaj geçmişi bulunamadı.\n")
            self.text_area.config(state='disabled')
            return
            
        for msg in messages:
            try:
                timestamp = msg.get('timestamp', '')
                sender = msg.get('sender', 'Bilinmeyen')
                encrypted_msg = msg.get('message', '')
                
                # Decrypt the message
                try:
                    decrypted_msg = decrypt_message(self.key, encrypted_msg)
                except:
                    decrypted_msg = encrypted_msg  # If decryption fails, use the original message
                
                # Format the message with timestamp and sender
                if sender == self.username:
                    prefix = f"Sen ({timestamp}): " if timestamp else "Sen: "
                else:
                    prefix = f"{sender} ({timestamp}): " if timestamp else f"{sender}: "
                
                self.text_area.insert(tk.END, prefix + decrypted_msg + "\n\n")
                
            except Exception as e:
                print(f"[HISTORY ERROR] Mesaj işlenirken hata: {e}")
                self.text_area.insert(tk.END, f"[HATA] Mesaj yüklenemedi: {e}\n")
        
        self.text_area.see(tk.END)
        self.text_area.config(state='disabled')
        self.append_text("✅ Mesaj geçmişi yüklendi\n")

    def append_text(self, text):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, text)
        self.text_area.see(tk.END)
        self.text_area.config(state='disabled')

    def close(self):
        """Uygulama kapatılırken çağrılır"""
        self.stop_event.set()
        
        # Listener thread'in bitmesini bekle
        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2.0)
        
        # Socket'i temizle
        self.cleanup_socket()
        
        # Pencereyi kapat
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleChatUI(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()