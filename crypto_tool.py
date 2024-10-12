import sys
sys.path.append(r"C:\Python312\Lib\site-packages")
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import os

# AES functions
def generate_aes_key():
    key = get_random_bytes(32)  # AES-256
    return key

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b64encode(cipher.nonce + tag + ciphertext)

def aes_decrypt(enc_data, key):
    enc_data = b64decode(enc_data)
    nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# RSA functions
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(data, public_key):
    rsa_public_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    return b64encode(cipher_rsa.encrypt(data))

def rsa_decrypt(enc_data, private_key):
    rsa_private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    return cipher_rsa.decrypt(b64decode(enc_data))

# Encrypt and Decrypt Files
def encrypt_file_aes(filename, key):
    with open(filename, 'rb') as f:
        data = f.read()
    encrypted_data = aes_encrypt(data, key)
    with open(filename + ".enc", 'wb') as f:
        f.write(encrypted_data)
    print(f"File {filename} encrypted successfully.")

def decrypt_file_aes(filename, key):
    with open(filename, 'rb') as f:
        enc_data = f.read()
    decrypted_data = aes_decrypt(enc_data, key)
    with open(filename.replace(".enc", ""), 'wb') as f:
        f.write(decrypted_data)
    print(f"File {filename} decrypted successfully.")

def encrypt_file_rsa(filename, public_key):
    with open(filename, 'rb') as f:
        data = f.read()
    encrypted_data = rsa_encrypt(data, public_key)
    with open(filename + ".enc", 'wb') as f:
        f.write(encrypted_data)
    print(f"File {filename} encrypted successfully with RSA.")

def decrypt_file_rsa(filename, private_key):
    with open(filename, 'rb') as f:
        enc_data = f.read()
    decrypted_data = rsa_decrypt(enc_data, private_key)
    with open(filename.replace(".enc", ""), 'wb') as f:
        f.write(decrypted_data)
    print(f"File {filename} decrypted successfully with RSA.")

# Interactive tool
def main():
    print("Welcome to the Cryptography Tool")
    print("1. AES Encryption/Decryption (Text)")
    print("2. RSA Encryption/Decryption (Text)")
    print("3. AES Encryption/Decryption (File)")
    print("4. RSA Encryption/Decryption (File)")
    
    choice = input("Select the encryption method: ")
    
    if choice == '1':
        # AES Text
        aes_key = generate_aes_key()
        print("Generated AES Key:", b64encode(aes_key).decode())

        data = input("Enter the data you want to encrypt: ")
        encrypted_data = aes_encrypt(data.encode(), aes_key)
        print(f"Encrypted Data: {encrypted_data.decode()}")

        if input("Decrypt the data? (y/n): ").lower() == 'y':
            decrypted_data = aes_decrypt(encrypted_data, aes_key)
            print(f"Decrypted Data: {decrypted_data.decode()}")

    elif choice == '2':
        # RSA Text
        private_key, public_key = generate_rsa_keys()
        print("Generated RSA Public Key:", public_key.decode())
        print("Generated RSA Private Key:", private_key.decode())

        data = input("Enter the data you want to encrypt: ")
        encrypted_data = rsa_encrypt(data.encode(), public_key)
        print(f"Encrypted Data: {encrypted_data.decode()}")

        if input("Decrypt the data? (y/n): ").lower() == 'y':
            decrypted_data = rsa_decrypt(encrypted_data, private_key)
            print(f"Decrypted Data: {decrypted_data.decode()}")

    elif choice == '3':
        # AES File
        aes_key = generate_aes_key()
        print("Generated AES Key:", b64encode(aes_key).decode())

        filename = input("Enter the file name you want to encrypt: ")
        encrypt_file_aes(filename, aes_key)

        if input("Decrypt the file? (y/n): ").lower() == 'y':
            decrypt_file_aes(filename + ".enc", aes_key)

    elif choice == '4':
        # RSA File
        private_key, public_key = generate_rsa_keys()
        print("Generated RSA Public Key:", public_key.decode())
        print("Generated RSA Private Key:", private_key.decode())

        filename = input("Enter the file name you want to encrypt: ")
        encrypt_file_rsa(filename, public_key)

        if input("Decrypt the file? (y/n): ").lower() == 'y':
            decrypt_file_rsa(filename + ".enc", private_key)

    else:
        print("Invalid option, please select a valid option.")
        
if __name__ == "__main__":
    main()
