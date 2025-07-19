Overview
This is a Flask-based web application that allows users to securely send and receive messages embedded in images using steganography and AES encryption. Users can sign up, log in, and send messages with optional file attachments and links, which are encrypted and embedded into a cover image. Receivers can extract and decrypt the message using a shared PIN.
Features

User Authentication: Sign-up and login functionality with password hashing (SHA-256).
Message Encryption: Messages are encrypted using AES (ECB mode) with a key derived from a user-provided PIN.
Steganography: Encrypted messages are embedded into the least significant bits (LSB) of a PNG image.
MySQL Database: Stores encrypted messages (ciphertexts) for retrieval.
File Uploads: Supports optional file attachments, encoded in base64 and included in the encrypted message.
PIN Validation: Ensures PINs are 5-32 characters long, with a mix of letters, numbers, and special characters.
Session Management: Simulated email sending and secure message retrieval with image deletion after successful decryption.

Requirements

Python 3.x
Flask
Pillow (PIL)
PyCryptoDome
mysql-connector-python
numpy
MySQL server (e.g., XAMPP with default configuration: host=localhost, user=root, password=empty, database=ciphertext_db)

Installation

Clone the repository:git clone <repository-url>
cd <repository-directory>


Install dependencies:pip install flask pillow pycryptodome mysql-connector-python numpy


Set up MySQL:
Start your MySQL server (e.g., via XAMPP).
Create a database named ciphertext_db.
The application will automatically create the necessary table (ciphertexts) on startup.


Create a static/uploads folder in the project directory to store uploaded and generated images.
Place a cover image named cover_image.png in the static folder for embedding messages.
Create a users.txt file in the project root to store user credentials (or it will be created automatically on first sign-up).

Usage

Run the application:python app.py


Access the application at http://localhost:5000 in your browser.
Sign Up: Create an account with a username and password.
Log In: Use your credentials to access the sender page.
Send a Message:
Enter sender and receiver email addresses, subject, message, optional link, and file.
Provide a PIN (5-32 characters, mixed letters/numbers/special characters).
The message is encrypted, stored in the database, and embedded into a stego image (stego_image.png).


Receive a Message:
Access the receiver page with the stego image.
Enter the same PIN used by the sender to decrypt and extract the message.
View the message details (from, to, subject, message, link, and optional file).
The stego image is deleted after successful decryption.



Templates
The application requires the following HTML templates in the templates folder:

signup.html: For user registration.
login.html: For user login.
sender.html: For composing and sending messages.
receiver.html: For extracting and viewing messages.

Security Notes

PIN Security: The PIN is critical for encryption/decryption. Share it securely with the recipient.
AES Mode: Uses ECB mode for simplicity; consider CBC mode for enhanced security in production.
Password Storage: Passwords are hashed with SHA-256 and stored in users.txt.
File Handling: Uploaded
