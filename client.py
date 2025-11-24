# client.py
import socket
import shutil
import os
import time
from utils import lsb_hide, des_encrypt, des_decrypt

HOST = '127.0.0.1'
PORT = 65432

class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = ""
        self.password = "" 
    
    def connect(self):
        self.sock.connect((HOST, PORT))
    
    def register(self):
        print("\n=== GÜVENLİ MESAJLAŞMA KAYIT ===")
        self.username = input("Kullanıcı Adı: ")
        self.password = input("Parola (Anahtar): ")
        raw_image = input("Kaynak Resim Adı (örn: kedi.png): ")
        
        if not os.path.exists(raw_image):
            print("HATA: Belirtilen resim dosyası bulunamadı!")
            return False

        # 1. Parolayı resme gizle
        stego_name = f"{self.username}_stego.png"
        lsb_hide(raw_image, stego_name, self.password)
        print(f"[CLIENT] Parola gizlendi -> {stego_name}")
        
        # 2. Sunucuya dosya transferi simülasyonu (Kopyalama)
        server_path = f"server_received_{stego_name}"
        shutil.copy(stego_name, server_path)
        
        # 3. Kayıt isteği gönder
        req = f"REGISTER|{self.username}|{stego_name}"
        self.sock.send(req.encode('utf-8'))
        resp = self.sock.recv(1024).decode('utf-8')
        
        if "BASARILI" in resp:
            print("[SİSTEM] Kayıt Başarılı!")
            return True
        else:
            print(f"[SİSTEM] Hata: {resp}")
            return False

    def chat_loop(self):
        while True:
            print("\n1. Kullanıcıları Gör | 2. Mesaj Yaz | 3. Kutuyu Kontrol Et | 4. Çıkış")
            choice = input("Seçim: ")
            
            if choice == '1':
                self.sock.send("LIST_USERS|".encode('utf-8'))
                resp = self.sock.recv(4096).decode('utf-8')
                print(f"Aktif Kullanıcılar: {resp.split('|')[1]}")
                
            elif choice == '2':
                target = input("Kime: ")
                msg = input("Mesaj: ")
                
                # Mesajı KENDİ anahtarımızla şifreliyoruz
                enc_msg = des_encrypt(msg, self.password)
                self.sock.send(f"SEND_MSG|{target}|{enc_msg}".encode('utf-8'))
                print(self.sock.recv(1024).decode('utf-8'))
                
            elif choice == '3':
                self.sock.send("CHECK_INBOX|".encode('utf-8'))
                resp = self.sock.recv(4096).decode('utf-8')
                
                if "EMPTY" in resp:
                    print("Yeni mesaj yok.")
                else:
                    raw_msgs = resp.split('|')[1].split(';')
                    print("\n--- GELEN KUTUSU ---")
                    for item in raw_msgs:
                        sender, enc_msg = item.split(':')
                        # Gelen mesajı yine KENDİ anahtarımızla çözüyoruz
                        # (Çünkü sunucu bizim için bizim anahtarımızla tekrar şifreledi)
                        plain = des_decrypt(enc_msg, self.password)
                        print(f"[{sender}]: {plain}")
                        
            elif choice == '4':
                break

if __name__ == "__main__":
    # Test için varsayılan bir resim yoksa oluştur
    if not os.path.exists("manzara.png"):
        from PIL import Image
        img = Image.new('RGB', (100, 100), color='blue')
        img.save('manzara.png')
        print("Not: Test için 'manzara.png' oluşturuldu.")

    c = Client()
    c.connect()
    if c.register():
        c.chat_loop() 