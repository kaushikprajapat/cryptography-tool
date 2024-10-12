Cryptography Tool

This is a Python-based cryptography tool that provides functionalities for both AES (Advanced Encryption Standard) and RSA (Rivest–Shamir–Adleman) encryption and decryption. The tool supports both text and file encryption/decryption.


Features
AES Encryption/Decryption: Encrypt and decrypt text and files using AES-256.
RSA Encryption/Decryption: Generate RSA keys and encrypt/decrypt text and files using RSA.
Dependencies

To run this tool, you'll need to install the pycryptodome library. You can do this using pip:


bash
Copy code
pip install pycryptodome
Supported Operating Systems
This tool is compatible with all major operating systems, including:

Windows
Linux
macOS
Docker
Usage
Clone the repository:


bash
Copy code
git clone https://github.com/kaushikprajapat/cryptography-tool.git
cd cryptography-tool
Run the tool:


Execute the script with Python:

bash
Copy code
python your_script_name.py
Replace your_script_name.py with the actual name of your Python file.

Follow the interactive prompts to select the desired encryption/decryption method (AES or RSA) and input your data or file name.


Functions Overview
AES Functions


generate_aes_key(): Generates a random AES key.
aes_encrypt(data, key): Encrypts the given data using the specified AES key.
aes_decrypt(enc_data, key): Decrypts the encrypted data using the specified AES key.
RSA Functions


generate_rsa_keys(): Generates a pair of RSA keys (public and private).
rsa_encrypt(data, public_key): Encrypts the given data using the specified RSA public key.
rsa_decrypt(enc_data, private_key): Decrypts the encrypted data using the specified RSA private key.
File Operations


encrypt_file_aes(filename, key): Encrypts the specified file using AES.
decrypt_file_aes(filename, key): Decrypts the specified AES-encrypted file.
encrypt_file_rsa(filename, public_key): Encrypts the specified file using RSA.
decrypt_file_rsa(filename, private_key): Decrypts the specified RSA-encrypted file.
