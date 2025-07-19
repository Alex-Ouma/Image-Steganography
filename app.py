from flask import Flask, request, render_template, send_file, redirect, url_for, flash
import os
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import re
import base64
import mysql.connector
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DB_FILE = 'ciphertext.db'
USER_DB = 'users.txt'

# MySQL configuration
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',  # Default XAMPP MySQL user
    'password': '',  # Default XAMPP MySQL password is empty
    'database': 'ciphertext_db'
}

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize MySQL database
def init_db():
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ciphertexts 
                 (id INT AUTO_INCREMENT PRIMARY KEY, 
                  ciphertext BLOB NOT NULL, 
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()
    print("MySQL database initialized.")

init_db()

def pad(data):
    padding_len = 16 - (len(data) % 16)
    padding = bytes([padding_len] * padding_len)
    print(f"Padding data with {padding_len} bytes: {padding.hex()}")
    return data + padding

def unpad(data):
    if len(data) < 1:
        raise ValueError("Data too short for unpadding")
    padding_len = data[-1]
    print(f"Unpadding data, padding length: {padding_len}")
    if padding_len > len(data) or padding_len == 0 or padding_len > 16:
        raise ValueError(f"Invalid padding length: {padding_len}")
    return data[:-padding_len]

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode('utf-8'))
    print(f"Padded message: {padded_message.hex()}")
    ciphertext = cipher.encrypt(padded_message)
    print(f"Encrypted ciphertext: {ciphertext.hex()}")
    return ciphertext

def decrypt_message(ciphertext, key):
    try:
        if len(ciphertext) % 16 != 0:
            raise ValueError(f"Ciphertext length {len(ciphertext)} is not a multiple of 16 bytes")
        print(f"Decrypting ciphertext: {ciphertext.hex()}, length: {len(ciphertext)} bytes")
        cipher = AES.new(key, AES.MODE_ECB)
        padded_message = cipher.decrypt(ciphertext)
        print(f"Decrypted padded message: {padded_message.hex()}")
        plaintext = unpad(padded_message).decode('utf-8') 
        print(f"Decrypted plaintext (raw): {plaintext}")
        return plaintext
    except ValueError as ve:
        print(f"Decryption error (ValueError): {ve}")
        return None
    except UnicodeDecodeError as ude:
        print(f"Decryption error (UnicodeDecodeError): {ude}")
        return None
    except Exception as e:
        print(f"Decryption error (Other): {e}")
        return None

def embed_message(image_path, data):
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = np.array(img)
        height, width, channels = pixels.shape
        print(f"Image dimensions: {width}x{height}, channels: {channels}")
        
        binary_data = ''.join(format(byte, '08b') for byte in data)
        data_length = len(data)
        length_binary = format(data_length, '032b')
        print(f"Embedding data length: {data_length} bytes, binary: {length_binary}")
        
        payload = length_binary + binary_data
        total_bits = len(payload)
        print(f"Total bits to embed (length + data): {total_bits}")
        print(f"Binary data to embed (first 64 bits): {binary_data[:64]}...")
        
        if total_bits > width * height * 3:
            raise ValueError(f"Data too large for image: {total_bits} bits vs {width * height * 3} available bits")
        
        bit_idx = 0
        for i in range(height):
            for j in range(width):
                for k in range(3):
                    if bit_idx < len(payload):
                        pixels[i, j, k] = (pixels[i, j, k] & ~1) | int(payload[bit_idx])
                        bit_idx += 1
                    else:
                        break
        
        print(f"Total bits embedded: {bit_idx}")
        stego_img = Image.fromarray(pixels)
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'stego_image.png')
        stego_img.save(output_path, 'PNG')
        print(f"Stego image saved at: {output_path}")
        
        extracted = extract_message(output_path)
        print(f"Verification extracted data: {extracted.hex() if extracted else 'None'}")
        if extracted != data:
            print(f"Embedding verification failed! Embedded: {data.hex()}, Extracted: {extracted.hex() if extracted else 'None'}")
        else:
            print("Embedding verification successful")
        
        return output_path
    except Exception as e:
        print(f"Embedding error: {e}")
        return None

def extract_message(stego_image_path):
    try:
        if not os.path.exists(stego_image_path):
            print(f"Image not found: {stego_image_path}")
            return None
        img = Image.open(stego_image_path).convert('RGB')
        pixels = np.array(img)
        height, width, channels = pixels.shape
        print(f"Extracting from image: {width}x{height}, channels: {channels}")
        
        binary_message = ''
        bit_idx = 0
        for i in range(height):
            for j in range(width):
                for k in range(3):
                    bit = (pixels[i, j, k] & 1)
                    binary_message += str(bit)
                    bit_idx += 1
                if bit_idx >= 32:
                    break
            if bit_idx >= 32:
                break
        
        length_binary = binary_message[:32]
        data_length = int(length_binary, 2)
        print(f"Extracted data length: {data_length} bytes, binary: {length_binary}")
        
        total_bits = data_length * 8
        print(f"Expected bits to extract for data: {total_bits}")
        
        binary_message = ''
        bit_idx = 0
        for i in range(height):
            for j in range(width):
                for k in range(3):
                    if bit_idx < 32 + total_bits:
                        bit = (pixels[i, j, k] & 1)
                        if bit_idx >= 32:
                            binary_message += str(bit)
                        bit_idx += 1
                    else:
                        break
                if bit_idx >= 32 + total_bits:
                    break
            if bit_idx >= 32 + total_bits:
                break
        
        print(f"Total bits extracted for data: {len(binary_message)}")
        print(f"Extracted binary data (first 64 bits): {binary_message[:64]}...")
        if len(binary_message) != total_bits:
            print(f"Error: Expected {total_bits} bits, but extracted {len(binary_message)} bits")
        
        byte_message = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
        data = bytes(int(b, 2) for b in byte_message if len(b) == 8)
        print(f"Extracted data: {data.hex()}, length: {len(data)} bytes")
        return data
    except Exception as e:
        print(f"Extraction error: {e}")
        return None

# Update database functions
def store_ciphertext(ciphertext):
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("INSERT INTO ciphertexts (ciphertext) VALUES (%s)", (ciphertext,))
    conn.commit()
    id = c.lastrowid
    conn.close()
    print(f"Stored ciphertext in MySQL with ID: {id}, data: {ciphertext.hex()}")
    return id

def retrieve_ciphertext(id):
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT ciphertext FROM ciphertexts WHERE id = %s", (id,))
    result = c.fetchone()
    conn.close()
    if result:
        print(f"Retrieved ciphertext from MySQL: {result[0].hex()}")
        return result[0]
    print(f"No ciphertext found for ID: {id}")
    return None

def validate_pin(pin):
    if not (5 <= len(pin) <= 32):
        return False, "PIN must be between 5 and 32 characters long."
    has_letter = any(c.isalpha() for c in pin)
    has_number = any(c.isdigit() for c in pin)
    has_special = any(not c.isalnum() for c in pin)
    if not (has_letter and has_number and has_special):
        return False, "PIN must contain a mix of letters, numbers, and special characters."
    return True, ""

@app.route('/')
def index():
    return redirect(url_for('signup'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        retype_password = request.form['retype_password']
        terms = request.form.get('terms')

        if password != retype_password:
            flash("Passwords do not match!", "error")
            return render_template('signup.html')

        if not terms:
            flash("You must agree to the terms and conditions!", "error")
            return render_template('signup.html')

        if os.path.exists(USER_DB):
            with open(USER_DB, 'r') as f:
                users = {line.split(':')[0]: line.split(':')[1].strip() for line in f}
            if username in users:
                flash("Username already exists! Please choose another.", "error")
                return render_template('signup.html')

        with open(USER_DB, 'a') as f:
            f.write(f"{username}:{hashlib.sha256(password.encode()).hexdigest()}\n")
        flash("Sign-up successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with open(USER_DB, 'r') as f:
            users = {line.split(':')[0]: line.split(':')[1].strip() for line in f}
        if username in users and users[username] == hashlib.sha256(password.encode()).hexdigest():
            return redirect(url_for('sender'))
        flash("Invalid credentials!", "error")
    return render_template('login.html')

@app.route('/sender', methods=['GET', 'POST'])
def sender():
    if request.method == 'POST':
        from_email = request.form['from_email']
        to_email = request.form['to_email']
        subject = request.form['subject']
        message = request.form['message']
        pin = request.form['pin'].strip()
        link = request.form.get('link', '')
        file = request.files.get('file')
        
        # Validate PIN
        is_valid, error_message = validate_pin(pin)
        if not is_valid:
            flash(error_message, "error")
            return render_template('sender.html')
        
        print(f"Sender PIN: {pin} (please note this PIN for decryption)")
        # Prepare data to encrypt
        data_to_encrypt = f"FROM:{from_email}|TO:{to_email}|SUBJECT:{subject}|MESSAGE:{message}"
        if link:
            data_to_encrypt += f"|LINK:{link}"
        if file and file.filename:
            file_data = file.read()
            file_b64 = base64.b64encode(file_data).decode('utf-8')
            data_to_encrypt += f"|FILE:{file.filename}|{file_b64}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        
        print(f"Data to encrypt: {data_to_encrypt}")
        # Encrypt and store in database
        key = hashlib.sha256(pin.encode('utf-8')).digest()[:16]
        print(f"Sender encryption key: {key.hex()}")
        ciphertext = encrypt_message(data_to_encrypt, key)
        print(f"Ciphertext before embedding: {ciphertext.hex()}, length: {len(ciphertext)} bytes")
        cipher_id = store_ciphertext(ciphertext)
        
        # Retrieve ciphertext from database and embed
        retrieved_ciphertext = retrieve_ciphertext(cipher_id)
        if not retrieved_ciphertext or retrieved_ciphertext != ciphertext:
            flash("Error retrieving ciphertext from database or data mismatch!", "error")
            print(f"Original ciphertext: {ciphertext.hex()}, Retrieved: {retrieved_ciphertext.hex() if retrieved_ciphertext else 'None'}")
            return render_template('sender.html')
        
        cover_image = 'static/cover_image.png'
        stego_image_path = embed_message(cover_image, retrieved_ciphertext)
        if not stego_image_path:
            flash("Failed to embed message into image!", "error")
            return render_template('sender.html')
        
        # Simulate email sending
        print(f"Simulated sending from {from_email} to {to_email} with subject {subject} and stego image: {stego_image_path}")
        flash("Message embedded and 'sent' successfully!", "success")
        return redirect(url_for('receiver', filename='stego_image.png'))
    return render_template('sender.html')

@app.route('/receiver/<filename>', methods=['GET', 'POST'])
def receiver(filename):
    stego_image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if request.method == 'POST':
        if request.form.get('action') == 'close':
            flash("Session closed.", "success")
            return redirect(url_for('login'))
        
        pin = request.form.get('pin', '').strip()
        if pin:
            is_valid, error_message = validate_pin(pin)
            if not is_valid:
                flash(error_message, "error")
                return render_template('receiver.html', image=filename)
            
            print(f"Receiver PIN: {pin} (ensure this matches the sender PIN)")
            key = hashlib.sha256(pin.encode('utf-8')).digest()[:16]
            print(f"Receiver decryption key: {key.hex()}")
            try:
                ciphertext = extract_message(stego_image_path)
                if not ciphertext:
                    flash("No message extracted from image!", "error")
                    return render_template('receiver.html', image=filename)
                print(f"Extracted ciphertext: {ciphertext.hex()}")
                plaintext = decrypt_message(ciphertext, key)
                if plaintext is None:
                    flash("Decryption failed! Incorrect PIN or corrupted data.", "error")
                    return render_template('receiver.html', image=filename)
                
                # Delete the stego image after successful decryption
                try:
                    if os.path.exists(stego_image_path):
                        os.remove(stego_image_path)
                        print(f"Successfully deleted stego image: {stego_image_path}")
                    else:
                        print(f"Stego image not found for deletion: {stego_image_path}")
                except Exception as e:
                    print(f"Error deleting stego image: {e}")
                
                # Clean plaintext and parse
                plaintext = plaintext.strip()
                print(f"Cleaned plaintext: {plaintext}")
                parts = plaintext.split('|')
                from_email = None
                to_email = None
                subject = None
                message = None
                link = None
                file_info = None
                
                for part in parts:
                    if part.startswith("FROM:"):
                        from_email = part[len("FROM:"):].strip()
                        print(f"Parsed from_email: {from_email}")
                    elif part.startswith("TO:"):
                        to_email = part[len("TO:"):].strip()
                        print(f"Parsed to_email: {to_email}")
                    elif part.startswith("SUBJECT:"):
                        subject = part[len("SUBJECT:"):].strip()
                        print(f"Parsed subject: {subject}")
                    elif part.startswith("MESSAGE:"):
                        message = part[len("MESSAGE:"):].strip()
                        print(f"Parsed message: {message}")
                    elif part.startswith("LINK:"):
                        link = part[len("LINK:"):].strip()
                        print(f"Parsed link: {link}")
                    elif part.startswith("FILE:"):
                        file_data = part[len("FILE:"):].strip()
                        if '|' in file_data:
                            file_name, file_b64 = file_data.split('|', 1)
                            file_info = (file_name.strip(), file_b64.strip())
                            print(f"Parsed file_info: {file_info}")
                        else:
                            print(f"Invalid FILE format in plaintext: {file_data}")
                
                print(f"Passing to template - from_email: {from_email}, to_email: {to_email}, subject: {subject}, message: {message}, link: {link}, file_info: {file_info}")
                return render_template('receiver.html', image=None, from_email=from_email, to_email=to_email, subject=subject, message=message, link=link, file_info=file_info)
            except Exception as e:
                flash(f"Error: {str(e)}", "error")
                print(f"Receiver error: {e}")
    return render_template('receiver.html', image=filename)

if __name__ == '__main__':
    app.run(debug=True)