from PIL import Image
import secrets
from typing import Optional

# Requires: cryptography (pip install cryptography)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 100000


def _bytes_to_bitstring(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)


def _bitstring_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))


def _derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password_bytes)


def _encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext includes tag
    # Pack: salt || nonce || ciphertext
    return salt + nonce + ciphertext


def _decrypt(payload: bytes, password: str) -> bytes:
    if len(payload) < SALT_SIZE + NONCE_SIZE + 1:
        raise ValueError("Encrypted payload too short")
    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ciphertext = payload[SALT_SIZE+NONCE_SIZE:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _pack_header(encrypted: bool, length: int) -> bytes:
    # 1 byte flags, 4 bytes big-endian length
    flags = 1 if encrypted else 0
    return bytes([flags]) + length.to_bytes(4, 'big')


def _unpack_header(header: bytes):
    if len(header) != 5:
        raise ValueError("Header must be 5 bytes")
    flags = header[0]
    encrypted = bool(flags & 1)
    length = int.from_bytes(header[1:5], 'big')
    return encrypted, length


def encode_image(image_path: str, secret_message: str, output_path: str, password: Optional[str] = None) -> None:
    """
    Encodes a UTF-8 text message into the least-significant bits of the RGB channels.
    If password is provided, the message is encrypted with AES-GCM (password-derived key).
    The embedded payload is prefixed with a 5-byte header: 1 byte flags, 4 byte length (big-endian).
    Preserves alpha channel if present and saves as PNG (lossless).
    """
    img = Image.open(image_path).convert("RGBA")
    pixels = img.load()
    width, height = img.size

    message_bytes = secret_message.encode("utf-8")

    if password:
        payload = _encrypt(message_bytes, password)
        encrypted_flag = True
    else:
        payload = message_bytes
        encrypted_flag = False

    header = _pack_header(encrypted_flag, len(payload))
    data_bits = _bytes_to_bitstring(header + payload)

    capacity = width * height * 3  # using R,G,B channels (one bit each)
    if len(data_bits) > capacity:
        raise ValueError(f"Message too large to hide: need {len(data_bits)} bits, capacity is {capacity} bits.")

    data_index = 0
    total_bits = len(data_bits)

    for y in range(height):
        for x in range(width):
            if data_index >= total_bits:
                break
            r, g, b, a = pixels[x, y]
            # modify R, then G, then B bits (one LSB each) as needed
            new_r = (r & ~1) | int(data_bits[data_index]) if data_index < total_bits else r
            data_index += 1
            new_g = (g & ~1) | int(data_bits[data_index]) if data_index < total_bits else g
            data_index += 1
            new_b = (b & ~1) | int(data_bits[data_index]) if data_index < total_bits else b
            data_index += 1

            pixels[x, y] = (new_r, new_g, new_b, a)
        if data_index >= total_bits:
            break

    img.save(output_path, "PNG")
    print(f"[+] Message hidden successfully in {output_path} (used {total_bits} bits).")


def decode_image(image_path: str, password: Optional[str] = None) -> str:
    """
    Decodes a message previously encoded with encode_image.
    Reads the 5-byte header first (flags + 32-bit length), then reads exactly that many payload bytes.
    If the encrypted flag is set, the password must be provided to decrypt.
    """
    img = Image.open(image_path).convert("RGBA")
    pixels = img.load()
    width, height = img.size

    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b, a = pixels[x, y]
            bits.append(str(r & 1))
            bits.append(str(g & 1))
            bits.append(str(b & 1))

    bitstring = ''.join(bits)
    # Need at least 5 bytes = 40 bits for header
    if len(bitstring) < 40:
        raise ValueError("Image does not contain enough data to read header.")

    header_bits = bitstring[:40]
    header_bytes = _bitstring_to_bytes(header_bits)
    encrypted_flag, payload_length = _unpack_header(header_bytes)

    start = 40
    end = start + (payload_length * 8)
    if len(bitstring) < end:
        raise ValueError("Image does not contain the full hidden message (truncated).")

    payload_bits = bitstring[start:end]
    payload = _bitstring_to_bytes(payload_bits)

    if encrypted_flag:
        if not password:
            raise ValueError("Password required to decrypt the hidden message.")
        plaintext = _decrypt(payload, password)
    else:
        plaintext = payload

    return plaintext.decode("utf-8")


# --- Example usage ---
if __name__ == "__main__":
    # Hide message (without encryption)
    encode_image("input.png", "Top Secret Code: 48291", "hidden.png")

    # Hide message with password-based AES-GCM encryption
    encode_image("input.png", "My secret password-protected message", "hidden_enc.png", password="s3cr3t")

    # Read hidden message back (no password)
    message = decode_image("hidden.png")
    print(f"[+] Extracted Message: {message}")

    # Read encrypted hidden message back
    message_enc = decode_image("hidden_enc.png", password="s3cr3t")
    print(f"[+] Extracted Encrypted Message: {message_enc}")
