import socket
import threading
import json
import sqlite3
import base64
import os
from utils_des import decrypt_message, encrypt_message, extract_password_from_image

HOST = "0.0.0.0"
PORT = 5000

clients = {}           # {username: conn}
clients_lock = threading.Lock()

DB_PATH = "database.db"
IMAGES_DIR = "server_images"

# Resim klasörünü oluştur
os.makedirs(IMAGES_DIR, exist_ok=True)

def ensure_key_8bytes(key: str) -> str:
    """DES anahtarı 8 byte olmalı: truncate veya pad ile ayarla"""
    if len(key) >= 8:
        return key[:8]
    return key.ljust(8, '0')

# --- JSON iletişim yardımcıları ---
def send_json(conn: socket.socket, obj: dict):
    """Client ile uyumlu basit JSON gönderimi"""
    try:
        data = json.dumps(obj).encode('utf-8')
        conn.sendall(data)
        return True
    except Exception as e:
        print(f"[ERROR] JSON gönderimi başarısız: {e}")
        return False

def recv_json(conn: socket.socket, timeout=5.0):
    """Client ile uyumlu basit JSON alımı - timeout ile"""
    try:
        conn.settimeout(timeout)
        data = conn.recv(8192)  # Büyük resim için 8KB
        if not data:
            return None
        return json.loads(data.decode('utf-8'))
    except socket.timeout:
        return None
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON parse hatası: {e}")
        return None
    except Exception as e:
        print(f"[ERROR] JSON alımı başarısız: {e}")
        return None

# --- Veritabanı yardımcıları ---
def init_db():
    """Veritabanını başlat"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        key TEXT NOT NULL,
                        image_path TEXT
                    )""")
        c.execute("""CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        receiver TEXT NOT NULL,
                        message TEXT NOT NULL,
                        delivered INTEGER DEFAULT 0,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )""")
        conn.commit()
        conn.close()
        print("[DB] Veritabanı başarıyla başlatıldı")
    except Exception as e:
        print(f"[DB ERROR] Veritabanı başlatma hatası: {e}")

def register_user(username, key, image_path=None):
    """Kullanıcı kaydı"""
    if not username or not key:
        print("[REGISTER ERROR] Kullanıcı adı veya anahtar boş!")
        return False
    
    key8 = ensure_key_8bytes(key)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO users (username, key, image_path) VALUES (?, ?, ?)", 
                  (username, key8, image_path))
        conn.commit()
        conn.close()
        print(f"[REGISTER] ✅ {username} kayıt oldu (key: {key8[:4]}...)")
        return True
    except Exception as e:
        print(f"[REGISTER ERROR] {username} kayıt hatası: {e}")
        return False

def get_user_key(username):
    """Kullanıcı anahtarını getir"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT key FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        print(f"[DB ERROR] Anahtar getirme hatası {username}: {e}")
        return None

def user_exists(username):
    """Kullanıcının kayıtlı olup olmadığını kontrol et"""
    return get_user_key(username) is not None

def authenticate_user(username, key):
    """Kullanıcı giriş doğrulaması"""
    if not username or not key:
        return False
    
    stored_key = get_user_key(username)
    if not stored_key:
        return False
    
    # Compare the provided key with the stored key
    key8 = ensure_key_8bytes(key)
    return key8 == stored_key

def store_message(sender, receiver, enc_msg):
    """Mesajı veritabanına kaydet"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO messages (sender, receiver, message, delivered) VALUES (?, ?, ?, 0)",
                  (sender, receiver, enc_msg))
        conn.commit()
        msg_id = c.lastrowid
        conn.close()
        print(f"[STORE] 💾 Mesaj kaydedildi (ID: {msg_id}): {sender} -> {receiver}")
        return msg_id
    except Exception as e:
        print(f"[STORE ERROR] Mesaj kaydetme hatası: {e}")
        return None

def mark_message_delivered(msg_id):
    """Mesajı teslim edildi olarak işaretle"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE messages SET delivered=1 WHERE id=?", (msg_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] Mesaj işaretleme hatası: {e}")

def deliver_offline_messages(username, conn):
    """Çevrimdışı mesajları teslim et"""
    try:
        conn_db = sqlite3.connect(DB_PATH)
        c = conn_db.cursor()
        c.execute("SELECT id, sender, message, strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp FROM messages WHERE receiver=? AND delivered=0 ORDER BY timestamp", 
                  (username,))
        rows = c.fetchall()

        if rows:
            print(f"[OFFLINE] {username} için {len(rows)} çevrimdışı mesaj bulundu")
        
        delivered_count = 0
        for msg_id, sender, message, timestamp in rows:
            try:
                if send_json(conn, {
                    "type": "message", 
                    "from": sender, 
                    "data": message,
                    "timestamp": timestamp
                }):
                    mark_message_delivered(msg_id)
                    delivered_count += 1
                else:
                    print(f"[OFFLINE WARN] Mesaj gönderilemedi (ID: {msg_id})")
            except Exception as e:
                print(f"[OFFLINE ERROR] Mesaj teslim hatası (ID: {msg_id}): {e}")
        
        conn_db.commit()
        conn_db.close()
        
        if delivered_count > 0:
            print(f"[OFFLINE] {delivered_count} mesaj teslim edildi: {username}")
    except Exception as e:
        print(f"[OFFLINE ERROR] Çevrimdışı mesaj teslimi hatası: {e}")

def broadcast_user_list():
    """Tüm bağlı kullanıcılara güncel kullanıcı listesini gönder"""
    with clients_lock:
        user_list = list(clients.keys())
        for user_conn in clients.values():
            try:
                send_json(user_conn, {"type": "user_list", "users": user_list})
            except:
                continue

# --- Mesaj yönlendirme (decrypt + re-encrypt) ---
def store_or_forward(sender, receiver, encrypted_msg_from_sender):
    """Mesajı alıcıya yönlendir veya sakla"""
    
    # Alıcının kayıtlı olup olmadığını kontrol et
    if not user_exists(receiver):
        print(f"[FORWARD ERROR] Alıcı bulunamadı: {receiver}")
        return False
    
    sender_key = get_user_key(sender)
    receiver_key = get_user_key(receiver)

    if not sender_key or not receiver_key:
        print(f"[FORWARD ERROR] Anahtar eksik: sender={bool(sender_key)}, receiver={bool(receiver_key)}")
        return False

    try:
        # Önce sender ile deşifrele
        plaintext = decrypt_message(sender_key, encrypted_msg_from_sender)
        print(f"[DECRYPT] Mesaj deşifre edildi: {sender} -> {receiver}")
    except Exception as e:
        print(f"[DECRYPT ERROR] Şifre çözme hatası {sender} -> {receiver}: {e}")
        return False

    try:
        # Receiver için yeniden şifrele
        re_enc = encrypt_message(receiver_key, plaintext)
        print(f"[ENCRYPT] Mesaj yeniden şifrelendi: {receiver} anahtarıyla")
    except Exception as e:
        print(f"[ENCRYPT ERROR] Şifreleme hatası: {e}")
        return False

    # Store the message in the database first
    msg_id = store_message(sender, receiver, re_enc)
    
    # Eğer alıcı online ise doğrudan gönder
    with clients_lock:
        receiver_conn = clients.get(receiver)

    if receiver_conn:
        try:
            if send_json(receiver_conn, {"type": "message", "from": sender, "data": re_enc, "timestamp": ""}):
                print(f"[FORWARD] ✅ Mesaj iletildi: {sender} -> {receiver}")
                mark_message_delivered(msg_id)
                return True
            else:
                print(f"[FORWARD WARN] İletim başarısız, mesaj zaten kaydedildi")
                return True
        except Exception as e:
            print(f"[FORWARD ERROR] İletim sırasında hata, mesaj zaten kaydedildi: {e}")
            return True
    else:
        print(f"[STORE] 📦 {receiver} çevrimdışı, mesaj kaydedildi (ID: {msg_id})")
        return True

def cleanup_connection(conn, username):
    """Bağlantıyı temizle ve kapatmayı garanti et"""
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except:
        pass
    
    try:
        conn.close()
    except:
        pass
    
    if username:
        with clients_lock:
            if clients.get(username) == conn:
                del clients[username]
                print(f"[CLEANUP] {username} bağlantısı temizlendi")

# --- Client bağlantı işleyicisi ---
def handle_client(conn, addr):
    """Her client bağlantısını yönet"""
    print(f"[+] Yeni bağlantı: {addr}")
    username = None
    
    # Socket'e timeout ekle
    conn.settimeout(30.0)

    try:
        while True:
            message = recv_json(conn, timeout=30.0)
            if message is None:
                print(f"[-] Bağlantı kesildi veya timeout: {addr}")
                break

            mtype = message.get("type")
            
            if mtype == "login":
                username = message.get("username", "").strip()
                key = message.get("key", "")
                
                if not username:
                    send_json(conn, {"status": "error", "message": "Kullanıcı adı boş olamaz"})
                    continue
                
                if authenticate_user(username, key):
                    with clients_lock:
                        # Eğer kullanıcı zaten bağlıysa eski bağlantıyı kapat
                        if username in clients:
                            old_conn = clients[username]
                            try:
                                send_json(old_conn, {"type": "error", "message": "Başka bir yerden giriş yapıldı"})
                                cleanup_connection(old_conn, None)
                            except:
                                pass
                        clients[username] = conn
                    
                    send_json(conn, {"status": "login_success"})
                    print(f"[LOGIN] ✅ {username} giriş yaptı (toplam: {len(clients)} kullanıcı)")
                    
                    deliver_offline_messages(username, conn)
                    broadcast_user_list()
                else:
                    send_json(conn, {"status": "error", "message": "Kullanıcı adı veya şifre hatalı"})
                    
            elif mtype == "register":
                username = message.get("username", "").strip()
                image_data = message.get("image_data")
                
                if not username:
                    send_json(conn, {"status": "error", "message": "Kullanıcı adı boş olamaz"})
                    continue
                
                if not image_data:
                    send_json(conn, {"status": "error", "message": "Resim verisi eksik"})
                    continue
                
                try:
                    # 🔓 STEGANOGRAPHY: Resimden parolayı çıkart
                    image_path = os.path.join(IMAGES_DIR, f"{username}.png")
                    
                    # Base64'ü decode et ve kaydet
                    image_bytes = base64.b64decode(image_data)
                    with open(image_path, 'wb') as f:
                        f.write(image_bytes)
                    
                    # Resimden parolayı çıkart
                    extracted_key = extract_password_from_image(image_path)
                    print(f"[STEGO] 🔓 Resimden parola çıkartıldı: {username} -> {extracted_key[:4]}...")
                    
                    # Kullanıcıyı kaydet
                    if register_user(username, extracted_key, image_path):
                        with clients_lock:
                            if username in clients:
                                old_conn = clients[username]
                                try:
                                    send_json(old_conn, {"type": "error", "message": "Başka bir yerden giriş yapıldı"})
                                    cleanup_connection(old_conn, None)
                                except:
                                    pass
                            clients[username] = conn
                        
                        send_json(conn, {"status": "registered"})
                        print(f"[REGISTER] ✅ {username} online oldu (toplam: {len(clients)} kullanıcı)")
                        
                        deliver_offline_messages(username, conn)
                        broadcast_user_list()
                    else:
                        send_json(conn, {"status": "error", "message": "Kayıt başarısız"})
                        
                except Exception as e:
                    print(f"[REGISTER ERROR] Resim işleme hatası: {e}")
                    send_json(conn, {"status": "error", "message": f"Resim işleme hatası: {str(e)}"})
                    
            elif mtype == "get_users":
                with clients_lock:
                    user_list = list(clients.keys())
                send_json(conn, {"type": "user_list", "users": user_list})
                
            elif mtype == "get_history":
                with_user = message.get("with_user")
                if not username:
                    send_json(conn, {"type": "error", "message": "Önce giriş yapmalısınız"})
                    continue
                    
                if not with_user:
                    send_json(conn, {"type": "error", "message": "Lütfen bir kullanıcı seçin"})
                    continue
                    
                try:
                    conn_db = sqlite3.connect(DB_PATH)
                    c = conn_db.cursor()
                    
                    query = """
                        SELECT sender, message, strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp 
                        FROM messages 
                        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                        ORDER BY timestamp
                    """
                    params = (username, with_user, with_user, username)
                    
                    c.execute(query, params)
                    
                    messages = []
                    rows = c.fetchall()
                    print(f"[HISTORY] {len(rows)} mesaj bulundu: {username} <-> {with_user}")
                    
                    for row in rows:
                        messages.append({
                            'sender': row[0],
                            'message': row[1],
                            'timestamp': row[2]
                        })
                    
                    send_json(conn, {"type": "message_history", "messages": messages})
                    conn_db.close()
                    
                except Exception as e:
                    print(f"[HISTORY ERROR] {e}")
                    send_json(conn, {"type": "error", "message": str(e)})

            elif mtype == "message":
                sender = message.get("sender", "").strip()
                receiver = message.get("receiver", "").strip()
                encrypted_msg = message.get("data", "")
                
                if not sender or not receiver or not encrypted_msg:
                    print(f"[MESSAGE ERROR] Eksik bilgi")
                    continue
                
                print(f"[MESSAGE] 📨 Mesaj alındı: {sender} -> {receiver}")
                store_or_forward(sender, receiver, encrypted_msg)

            else:
                print(f"[UNKNOWN] Bilinmeyen mesaj tipi: {mtype}")

    except socket.timeout:
        print(f"[-] Timeout ({addr})")
    except Exception as e:
        print(f"[-] Hata ({addr}): {e}")
    finally:
        cleanup_connection(conn, username)
        if username:
            print(f"[LOGOUT] 👋 {username} offline oldu (toplam: {len(clients)} kullanıcı)")
            broadcast_user_list()
        print(f"[-] Bağlantı kapandı: {addr}")

# --- Sunucu başlat ---
def start_server():
    """Ana sunucu döngüsü"""
    print("=" * 60)
    print("🔐 Güvenli Chat Sunucusu (DES + Steganografi)")
    print("=" * 60)
    
    init_db()
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(5)
            print(f"[SERVER] ✅ Sunucu başlatıldı: {HOST}:{PORT}")
            print(f"[SERVER] 👂 Bağlantılar dinleniyor...\n")

            while True:
                try:
                    conn, addr = s.accept()
                    thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                    thread.start()
                except KeyboardInterrupt:
                    print("\n\n[SERVER] 🛑 Sunucu kapatılıyor...")
                    break
                except Exception as e:
                    print(f"[SERVER ERROR] ❌ Bağlantı kabul hatası: {e}")
    
    except Exception as e:
        print(f"[SERVER ERROR] ❌ Sunucu başlatma hatası: {e}")
    finally:
        with clients_lock:
            for username, conn in list(clients.items()):
                cleanup_connection(conn, username)
        print("[SERVER] 👋 Sunucu kapatıldı")

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[SERVER] 👋 Güle güle!")