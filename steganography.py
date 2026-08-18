from PIL import Image

def text_to_bin(text):
    # Convert string to binary representation
    return ''.join(format(ord(char), '08b') for char in text)

def bin_to_text(binary_data):
    # Convert binary back to string
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_text = ""
    for byte in all_bytes:
        decoded_text += chr(int(byte, 2))
    return decoded_text

def encode_image(image_path, secret_message, output_path):
    img = Image.open(image_path)
    # Add delimiter to know where secret ends
    secret_message += "#####"
    binary_secret = text_to_bin(secret_message)
    
    pixels = img.load()
    width, height = img.size
    
    data_index = 0
    data_length = len(binary_secret)
    
    for y in range(height):
        for x in range(width):
            if data_index < data_length:
                r, g, b = pixels[x, y][:3]
                
                # Modify the Least Significant Bit (LSB) of Red channel
                new_r = (r & ~1) | int(binary_secret[data_index])
                data_index += 1
                
                pixels[x, y] = (new_r, g, b)
            else:
                break
        if data_index >= data_length:
            break
            
    img.save(output_path, "PNG")
    print(f"[+] Message hidden successfully in {output_path}!")

def decode_image(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    
    binary_data = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y][:3]
            # Extract LSB from Red channel
            binary_data += str(r & 1)
            
    # Convert binary to text and split at delimiter
    decoded_text = bin_to_text(binary_data)
    secret_message = decoded_text.split("#####")[0]
    return secret_message

# --- Test Execution ---
if __name__ == "__main__":
    # Hide message
    encode_image("input.png", "Top Secret Code: 48291", "hidden.png")
    
    # Read hidden message back
    message = decode_image("hidden.png")
    print(f"[+] Extracted Message: {message}")