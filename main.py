from flask import Flask, request, send_file, render_template
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import io

app = Flask(__name__)

# Fungsi untuk mengenkripsi data menggunakan Caesar
def caesar_encrypt(data, shift):
    shift = shift % 256
    encrypted_data = bytearray(data)
    for i in range(len(data)):
        encrypted_data[i] = (data[i] + shift) % 256
    return bytes(encrypted_data)

# Fungsi untuk mendekripsi data menggunakan Caesar
def caesar_decrypt(data, shift):
    shift = shift % 256
    decrypted_data = bytearray(data)
    for i in range(len(data)):
        decrypted_data[i] = (data[i] - shift) % 256
    return bytes(decrypted_data)

# Fungsi untuk mengenkripsi data menggunakan Vigenere
def vigenere_encrypt(data, key):
    key = key.encode()  # Ubah key menjadi byte array
    key_length = len(key)
    encrypted_data = bytearray(data)
    for i in range(len(data)):
        encrypted_data[i] = (data[i] + key[i % key_length]) % 256
    return bytes(encrypted_data)

# Fungsi untuk mendekripsi data menggunakan Vigenere
def vigenere_decrypt(data, key):
    key = key.encode()  # Ubah key menjadi byte array
    key_length = len(key)
    decrypted_data = bytearray(data)
    for i in range(len(data)):
        decrypted_data[i] = (data[i] - key[i % key_length]) % 256
    return bytes(decrypted_data)

# Fungsi untuk mengenkripsi gambar dengan Caesar, Vigenere, dan AES
def encrypt_image(image_data, aes_key, aes_iv, vigenere_key, caesar_shift):
    # Enkripsi data dengan Caesar
    caesar_encrypted_data = caesar_encrypt(image_data, caesar_shift)

    # Enkripsi data dengan Vigenere
    vigenere_encrypted_data = vigenere_encrypt(caesar_encrypted_data, vigenere_key)

    # Padding untuk memastikan panjang data sesuai dengan block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(vigenere_encrypted_data) + padder.finalize()

    # Buat cipher AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Enkripsi data dengan AES
    final_encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return aes_key + aes_iv + final_encrypted_data  # Simpan key dan IV di awal file

# Fungsi untuk mendekripsi gambar dengan AES, Vigenere, dan Caesar
def decrypt_image(encrypted_data, vigenere_key, caesar_shift):
    aes_key = encrypted_data[:16]  # Baca key AES dari awal file
    aes_iv = encrypted_data[16:32]  # Baca IV dari file
    encrypted_data = encrypted_data[32:]

    # Buat cipher AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Dekripsi data dengan AES
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Hapus padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    vigenere_encrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    # Dekripsi data dengan Vigenere
    caesar_encrypted_data = vigenere_decrypt(vigenere_encrypted_data, vigenere_key)

    # Dekripsi data dengan Caesar
    final_decrypted_data = caesar_decrypt(caesar_encrypted_data, caesar_shift)

    return final_decrypted_data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'image' not in request.files:
        return 'No file part', 400

    file = request.files['image']
    if file.filename == '':
        return 'No selected file', 400

    image_data = file.read()
    aes_key = os.urandom(16)  # Menghasilkan kunci 128 bit secara acak untuk AES
    aes_iv = os.urandom(16)   # Menghasilkan IV secara acak untuk AES
    vigenere_key = 'wahyu'  # Kunci untuk Vigenere
    caesar_shift = 2024  # Pergeseran untuk Caesar cipher

    encrypted_data = encrypt_image(image_data, aes_key, aes_iv, vigenere_key, caesar_shift)

    encrypted_file = io.BytesIO(encrypted_data)
    encrypted_file.seek(0)

    return send_file(encrypted_file, as_attachment=True, attachment_filename='encrypted_image.jpg', mimetype='image/jpeg')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return 'No file part', 400

    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    encrypted_data = file.read()
    vigenere_key = 'wahyu'  # Kunci untuk Vigenere (harus sama dengan yang digunakan saat enkripsi)
    caesar_shift = 2024  # Pergeseran untuk Caesar cipher (harus sama dengan yang digunakan saat enkripsi)

    decrypted_data = decrypt_image(encrypted_data, vigenere_key, caesar_shift)

    decrypted_file = io.BytesIO(decrypted_data)
    decrypted_file.seek(0)

    return send_file(decrypted_file, as_attachment=True, attachment_filename='decrypted_image.jpg', mimetype='image/jpeg')

if __name__ == '__main__':
    app.run(debug=True)
