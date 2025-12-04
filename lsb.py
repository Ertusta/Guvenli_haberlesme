from PIL import Image, ImageDraw
import numpy as np
import os
import random

def text_to_bin(text):
    return ''.join(format(ord(char), '08b') for char in text)

def bin_to_text(binary_string):
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))

def generate_random_image(width=800, height=600):
    img = Image.new('RGB', (width, height), color=(
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    ))
    
    draw = ImageDraw.Draw(img)
    
    for _ in range(20):
        # Generate coordinates in the correct order
        x1 = random.randint(0, width - 10)
        y1 = random.randint(0, height - 10)
        x2 = random.randint(x1 + 5, min(x1 + 100, width))
        y2 = random.randint(y1 + 5, min(y1 + 100, height))
        
        color = (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
        
        if random.choice([True, False]):
            draw.rectangle([x1, y1, x2, y2], fill=color)
        else:
            draw.ellipse([x1, y1, x2, y2], fill=color)
    
    return img

def encode_message(message, output_path, width=800, height=600):
    try:
        # Tam dosya yolu oluştur
        import os
        output_path = os.path.abspath(output_path)
        output_dir = os.path.dirname(output_path)
        
        # Eğer dizin yoksa oluştur
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        binary_msg = text_to_bin(message) + '1111111111111110'  # Delimiter
        
        # Kalan kod aynı...
        required_pixels = (len(binary_msg) // 3) + 1
        required_width = max(100, min(width, 2000))
        required_height = max(100, (required_pixels // required_width) + 1)
        
        img = generate_random_image(required_width, required_height)
        img_array = np.array(img)
        
        max_bits = img_array.shape[0] * img_array.shape[1] * 3
        binary_msg = binary_msg.ljust(max_bits, '0')
        
        data_index = 0
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                if data_index >= len(binary_msg):
                    break
                    
                r, g, b = img_array[i, j][:3]
                
                if data_index < len(binary_msg):
                    r = (r & 0xFE) | int(binary_msg[data_index])
                    data_index += 1
                if data_index < len(binary_msg):
                    g = (g & 0xFE) | int(binary_msg[data_index])
                    data_index += 1
                if data_index < len(binary_msg):
                    b = (b & 0xFE) | int(binary_msg[data_index])
                    data_index += 1
                
                img_array[i, j] = [r, g, b]
        
        Image.fromarray(img_array.astype('uint8'), 'RGB').save(output_path, 'PNG')
        print(f"✅ Mesaj başarıyla kaydedildi: {output_path}")
        return True
        
    except Exception as e:
        print(f"❌ Hata: {str(e)}")
        return False

def decode_message(image_path):
    try:
        image_path = os.path.abspath(image_path)
        print(f"📂 Görsel yolu: {image_path}")
        
        if not os.path.exists(image_path):
            return "❌ Görsel bulunamadı!"
            
        img = Image.open(image_path)
        img_array = np.array(img)
        binary_msg = ""
        delimiter = '1111111111111110'
        
        print(f"📊 Görsel boyutu: {img_array.shape}")
        
        # Tüm pikselleri oku
        for row in img_array:
            for pixel in row:
                r, g, b = pixel[:3]
                binary_msg += str(r & 1)
                binary_msg += str(g & 1)
                binary_msg += str(b & 1)
                
                # Son 16 biti kontrol et
                if len(binary_msg) >= len(delimiter) and binary_msg[-len(delimiter):] == delimiter:
                    message = binary_msg[:-len(delimiter)]
                    # Eğer mesaj çok kısa veya anlamsızsa, tüm veriyi kontrol et
                    if len(message) < 8:  # En az 1 karakter (8 bit) olmalı
                        continue
                    try:
                        return bin_to_text(message)
                    except:
                        continue
        
        # Eğer ayırıcı bulunamazsa, tüm veriyi oku
        print("⚠️ Ayırıcı bulunamadı, tüm veri okunuyor...")
        try:
            # Son 16 biti atla ve dene
            message = binary_msg[:-16] if len(binary_msg) > 16 else binary_msg
            return bin_to_text(message)
        except Exception as e:
            return f"❌ Mesaj çözülemedi: {str(e)}\nİkili veri: {binary_msg[:100]}..."
        
    except Exception as e:
        import traceback
        return f"❌ Hata: {str(e)}\n{traceback.format_exc()}"

def main():
    print("""
    🌟 LSB Steganografi Aracı
    ------------------------
    1. Görsele Mesaj Gizle
    2. Görselden Mesaj Çıkar
    """)
    
    try:
        choice = input("Seçiminiz (1/2): ").strip()
        
        if choice == '1':
            message = input("📝 Gizlenecek mesajı yazın: ").strip()
            if not message:
                raise ValueError("Mesaj boş olamaz")
                
            output_path = input("📁 Çıktı dosya adı (örn: gizli_mesaj.png): ").strip()
            if not output_path:
                output_path = "gizli_mesaj.png"
            if not output_path.lower().endswith('.png'):
                output_path += '.png'
                
            encode_message(message, output_path)
            
        elif choice == '2':
            image_path = input("📂 Mesaj içeren görselin yolu: ").strip()
            if not os.path.exists(image_path):
                image_path = os.path.join(os.getcwd(), image_path)
                if not os.path.exists(image_path):
                    print("❌ Görsel bulunamadı!")
                    return
            print("🔍 Mesaj çözülüyor...")
            message = decode_message(image_path)
            print("\n📜 Gizli Mesaj:")
            print(message)
            
        else:
            print("❌ Geçersiz seçim!")
            
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {str(e)}")

if __name__ == "__main__":
    main()