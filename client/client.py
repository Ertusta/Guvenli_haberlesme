import socket
import json
import threading
import sys
from utils_des import encrypt_message, decrypt_message

SERVER_IP = "127.0.0.1"
PORT = 5000

def listen_server(sock, key, stop_event):
    """Sunucudan gelen mesajları dinler."""
    while not stop_event.is_set():
        try:
            sock.settimeout(1.0)  # Timeout ekle ki stop_event kontrol edilebilsin
            data = sock.recv(4096)
            if not data:
                print("\n❌ Sunucu bağlantısı kesildi")
                break
            
            try:
                message = json.loads(data.decode())
            except json.JSONDecodeError:
                print("\n⚠️ Geçersiz veri alındı")
                continue

            # Kullanıcı kayıt onayı
            if message.get("status") == "registered":
                print("\n✅ Sunucu kaydı başarılı!\n")

            # Mesaj geldiğinde
            elif message.get("type") == "message":
                encrypted = message.get("data")
                sender = message.get("from")
                if encrypted and sender:
                    try:
                        decrypted = decrypt_message(key, encrypted)
                        print(f"\n📩 {sender}: {decrypted}")
                        print("Kime (alıcı adı): ", end="", flush=True)
                    except Exception as e:
                        print(f"\n⚠️ Mesaj şifresi çözülemedi: {e}")
                        print("Kime (alıcı adı): ", end="", flush=True)

        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n❌ Sunucu bağlantısı koptu: {e}")
            break


def main():
    print("=" * 50)
    print("🔐 Güvenli Chat Uygulaması")
    print("=" * 50)
    
    username = input("Kullanıcı adı: ").strip()
    if not username:
        print("❌ Kullanıcı adı boş olamaz!")
        return
    
    key = input("Şifreleme anahtarı (8 karakter): ").strip()
    if len(key) < 8:
        key = key.ljust(8, '0')  # 8 karakterden kısa ise 0 ile doldur
        print(f"ℹ️ Anahtar 8 karaktere tamamlandı: {key}")
    elif len(key) > 8:
        key = key[:8]  # 8 karakterden uzun ise kes
        print(f"ℹ️ Anahtar 8 karaktere kısaltıldı: {key}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"\n🔄 Sunucuya bağlanılıyor ({SERVER_IP}:{PORT})...")
        sock.connect((SERVER_IP, PORT))
        print("✅ Bağlantı kuruldu!")
    except Exception as e:
        print(f"❌ Sunucuya bağlanılamadı: {e}")
        return

    # Register isteği
    register_data = json.dumps({
        "type": "register",
        "username": username,
        "key": key
    }).encode()
    
    try:
        sock.send(register_data)
        print("🔄 Kayıt isteği gönderildi, onay bekleniyor...")
    except Exception as e:
        print(f"❌ Kayıt isteği gönderilemedi: {e}")
        sock.close()
        return

    # Kayıt onayını bekle
    try:
        sock.settimeout(5.0)  # 5 saniye timeout
        response = sock.recv(4096)
        sock.settimeout(None)  # Timeout'u kaldır
        
        confirm = json.loads(response.decode())
        if confirm.get("status") == "registered":
            print("✅ Sunucuya başarıyla kaydoldunuz!\n")
        else:
            error_msg = confirm.get("message", "Bilinmeyen hata")
            print(f"❌ Kayıt başarısız: {error_msg}")
            sock.close()
            return
    except socket.timeout:
        print("❌ Sunucu yanıt vermedi (zaman aşımı)")
        sock.close()
        return
    except Exception as e:
        print(f"❌ Kayıt sırasında hata: {e}")
        sock.close()
        return

    # Sunucuyu dinleyen thread başlat
    stop_event = threading.Event()
    listener = threading.Thread(target=listen_server, args=(sock, key, stop_event), daemon=True)
    listener.start()

    print("💬 Mesajlaşmaya başlayabilirsiniz!")
    print("ℹ️  Çıkmak için Ctrl+C yapın\n")

    # Mesaj gönderme döngüsü
    try:
        while True:
            receiver = input("Kime (alıcı adı): ").strip()
            if not receiver:
                print("⚠️ Alıcı adı boş olamaz!")
                continue
                
            message = input("Mesaj: ").strip()
            if not message:
                print("⚠️ Mesaj boş olamaz!")
                continue

            try:
                enc_msg = encrypt_message(key, message)
            except Exception as e:
                print(f"❌ Mesaj şifrelenemedi: {e}")
                continue

            msg_data = json.dumps({
                "type": "message",
                "sender": username,
                "receiver": receiver,
                "data": enc_msg
            }).encode()
            
            try:
                sock.send(msg_data)
                print("✅ Mesaj gönderildi!\n")
            except Exception as e:
                print(f"❌ Mesaj gönderilemedi: {e}")
                break

    except KeyboardInterrupt:
        print("\n\n👋 Çıkış yapılıyor...")
    except Exception as e:
        print(f"\n❌ Beklenmeyen hata: {e}")
    finally:
        print("🔄 Bağlantı kapatılıyor...")
        stop_event.set()
        sock.close()
        listener.join(timeout=2)
        print("✅ Bağlantı kapatıldı. Güle güle!")


if __name__ == "__main__":
    main()