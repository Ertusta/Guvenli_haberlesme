from Crypto.Cipher import DES
import base64
import io
import os
import math
import binascii
try:
    from PIL import Image
except Exception:
    Image = None

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_message(key, msg):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    return base64.b64encode(des.encrypt(pad(msg).encode())).decode()

def decrypt_message(key, enc_msg):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    return des.decrypt(base64.b64decode(enc_msg)).decode().strip()


def _to_bits(data_bytes: bytes):
    bits = []
    for b in data_bytes:
        for i in range(8)[::-1]:
            bits.append((b >> i) & 1)
    return bits


def _from_bits(bits):
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        b.append(byte)
    return bytes(b)


def embed_password_in_image(image_path: str, password: str, out_path: str = None) -> str:
    """Embed a UTF-8 password into an image using simple LSB steganography.
    Returns the path to the saved image containing the hidden password.
    """
    if Image is None:
        raise RuntimeError("Pillow is required for steganography (pip install pillow)")

    if out_path is None:
        dirname = os.path.join(os.path.dirname(__file__), "server_images")
        os.makedirs(dirname, exist_ok=True)
        out_path = os.path.join(dirname, os.path.basename(image_path))

    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    width, height = img.size
    capacity = width * height * 3  # bits

    pwd_bytes = password.encode('utf-8')
    # store length as 32-bit header
    header = len(pwd_bytes).to_bytes(4, 'big')
    payload = header + pwd_bytes
    bits = _to_bits(payload)

    if len(bits) > capacity:
        raise ValueError(f"Image too small to store password ({len(bits)} bits needed, {capacity} available)")

    new_pixels = []
    bit_idx = 0
    for r, g, b in pixels:
        nr, ng, nb = r, g, b
        for color in range(3):
            if bit_idx < len(bits):
                if color == 0:
                    nr = (nr & ~1) | bits[bit_idx]
                elif color == 1:
                    ng = (ng & ~1) | bits[bit_idx]
                else:
                    nb = (nb & ~1) | bits[bit_idx]
                bit_idx += 1
        new_pixels.append((nr, ng, nb))

    img2 = Image.new('RGB', img.size)
    img2.putdata(new_pixels)
    img2.save(out_path, format='PNG')
    return out_path


def extract_password_from_image(image_path: str) -> str:
    """Extract password embedded with `embed_password_in_image`.
    Returns the UTF-8 password string.
    """
    if Image is None:
        raise RuntimeError("Pillow is required for steganography (pip install pillow)")

    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())

    # first retrieve 32-bit length header
    bits = []
    for r, g, b in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    header_bits = bits[:32]
    header_bytes = _from_bits(header_bits)
    length = int.from_bytes(header_bytes, 'big')

    total_bits = 32 + length * 8
    if total_bits > len(bits):
        raise ValueError("Image does not contain a complete password or is corrupted")

    payload_bits = bits[32:total_bits]
    payload_bytes = _from_bits(payload_bits)
    return payload_bytes.decode('utf-8')
