# server.py
import socket
import threading
import os
from utils import lsb_reveal, des_encrypt, des_decrypt

HOST = '127.0.0.1'
PORT = 65432

# Veritabanı (RAM üzerinde tutulur)
users_db = {}   # { 'ali': '123456' }
mailboxes = {}  # { 'ali': ['veli:ŞifreliMesaj'] }

def handle_client(conn, addr):
    print(f"[BAĞLANTI] {addr} bağlandı.")
    current_user = None
    
    while True:
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data: break
            
            # Komut ayrıştırma
            parts = data.split('|', 1)
            command = parts[0]
            payload = parts[1] if len(parts) > 1 else ""
            
            if command == "REGISTER":
                # payload: username|image_filename
                username, img_name = payload.split('|')
                server_img_path = f"server_received_{img_name}"
                
                if os.path.exists(server_img_path):
                    # 1. Görüntüden Parolayı Çıkar
                    extracted_key = lsb_reveal(server_img_path)
                    users_db[username] = extracted_key
                    mailboxes[username] = []
                    
                    print(f"[KAYIT] Kullanıcı: {username}, Çıkarılan Anahtar: {extracted_key}")
                    conn.send("KAYIT_BASARILI".encode('utf-8'))
                    current_user = username
                else:
                    conn.send("HATA: Görüntü sunucuda bulunamadı.".encode('utf-8'))

            elif command == "LIST_USERS":
                active_users = ",".join(users_db.keys())
                conn.send(f"USERS|{active_users}".encode('utf-8'))

            elif command == "SEND_MSG":
                # payload: target_user|encrypted_msg
                target_user, encrypted_msg_sender = payload.split('|')
                
                if target_user in users_db:
                    sender_key = users_db[current_user]
                    receiver_key = users_db[target_user]
                    
                    # 2. Sunucu: Gönderenin anahtarıyla çöz
                    plain_text = des_decrypt(encrypted_msg_sender, sender_key)
                    print(f"[SUNUCU LOG] {current_user} -> {target_user} (İçerik: {plain_text})")
                    
                    # 3. Sunucu: Alıcının anahtarıyla tekrar şifrele
                    encrypted_msg_receiver = des_encrypt(plain_text, receiver_key)
                    
                    # Kutuya bırak
                    mailboxes[target_user].append(f"{current_user}:{encrypted_msg_receiver}")
                    conn.send("MESAJ_ILETILDI".encode('utf-8'))
                else:
                    conn.send("HATA: Kullanıcı bulunamadı.".encode('utf-8'))

            elif command == "CHECK_INBOX":
                if current_user in mailboxes and mailboxes[current_user]:
                    # Mesajları birleştirip gönder
                    all_msgs = ";".join(mailboxes[current_user])
                    conn.send(f"INBOX|{all_msgs}".encode('utf-8'))
                    mailboxes[current_user] = [] # Okunanları sil
                else:
                    conn.send("INBOX|EMPTY".encode('utf-8'))

        except Exception as e:
            print(f"Hata oluştu: {e}")
            break
    
    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SUNUCU] {HOST}:{PORT} üzerinde çalışıyor...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()