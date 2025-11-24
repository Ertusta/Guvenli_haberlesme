# utils.py
from Crypto.Cipher import DES
from PIL import Image
import base64

def pad(text):
    # Metni 8'in katı olacak şekilde boşlukla tamamlar
    while len(text) % 8 != 0:
        text += ' '
    return text

def des_encrypt(msg, key):
    # HATA ÖNLEME: Anahtar 8 byte olmalı. Kısa ise '0' ekle, uzunsa kes.
    valid_key = key[:8].ljust(8, '0')
    
    des = DES.new(valid_key.encode('utf-8'), DES.MODE_ECB)
    # Önce pad yap, sonra encrypt et, en son base64'e çevir
    return base64.b64encode(des.encrypt(pad(msg).encode())).decode()

def des_decrypt(enc_msg, key):
    try:
        valid_key = key[:8].ljust(8, '0')
        des = DES.new(valid_key.encode('utf-8'), DES.MODE_ECB)
        # Base64 çöz, decrypt et, sondaki boşlukları strip() ile sil
        return des.decrypt(base64.b64decode(enc_msg)).decode().strip()
    except Exception as e:
        return f"HATA: {e}"

# --- 2. STEGANOGRAFİ (LSB) KODU ---
def lsb_hide(image_path, output_path, secret_text):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = img.load()
    
    # Bitiş belirteci ekle
    secret_text += "#####"
    binary_secret = ''.join(format(ord(i), '08b') for i in secret_text)
    data_len = len(binary_secret)
    data_index = 0
    
    width, height = img.size
    for y in range(height):
        for x in range(width):
            if data_index < data_len:
                r, g, b = pixels[x, y]
                r = (r & 254) | int(binary_secret[data_index])
                pixels[x, y] = (r, g, b)
                data_index += 1
            else:
                break
    img.save(output_path)
    return output_path

def lsb_reveal(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = img.load()
    
    binary_data = ""
    width, height = img.size
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_str = ""
    for byte in all_bytes:
        try:
            char = chr(int(byte, 2))
            decoded_str += char
            if decoded_str.endswith("#####"):
                return decoded_str[:-5]
        except:
            break
    return "Veri Bulunamadı"