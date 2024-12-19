import rsa
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

class EncryptionTool:
    """
    Powerful Encryption Tool with RSA and AES
    Developed by ybouanan
    """

    def __init__(self, key_size=2048):

        self.key_size = key_size
        self.public_key_file = "public_key.pem"
        self.private_key_file = "private_key.pem"
        self.encrypted_file = "encrypted_message.txt"
        self.decrypted_file = "decrypted_message.txt"


        self.aes_key_file = "aes_key.bin"
        self.aes_encrypted_file = "aes_encrypted_message.txt"
        self.aes_decrypted_file = "aes_decrypted_message.txt"
        self.aes_encrypted_key_file = "aes_encrypted_key.bin"


    def generate_rsa_keys(self):
        """Generate RSA key pair and save to files."""
        public_key, private_key = rsa.newkeys(self.key_size)


        with open(self.public_key_file, 'wb') as pub_file:
            pub_file.write(public_key.save_pkcs1())


        with open(self.private_key_file, 'wb') as priv_file:
            priv_file.write(private_key.save_pkcs1())

        print("RSA keys generated and saved successfully.")

    def rsa_encrypt(self, data):
        """Encrypt data using the RSA public key."""
        if not os.path.exists(self.public_key_file):
            print("Error: Public key not found. Please generate RSA keys first.")
            return None

        with open(self.public_key_file, 'rb') as pub_file:
            public_key = rsa.PublicKey.load_pkcs1(pub_file.read())

        return rsa.encrypt(data, public_key)

    def rsa_decrypt(self, encrypted_data):
        """Decrypt data using the RSA private key."""
        if not os.path.exists(self.private_key_file):
            print("Error: Private key not found. Please generate RSA keys first.")
            return None

        with open(self.private_key_file, 'rb') as priv_file:
            private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

        try:
            return rsa.decrypt(encrypted_data, private_key)
        except rsa.DecryptionError:
            print("Error: RSA decryption failed. The data or key may be incorrect.")
            return None

    def generate_aes_key(self):
        """Generate a random AES key and save to file."""
        aes_key = secrets.token_bytes(32)  # 256-bit key
        with open(self.aes_key_file, 'wb') as key_file:
            key_file.write(aes_key)

        print("AES key generated and saved successfully.")

    def aes_encrypt_message(self, message):
        """Encrypt a message using AES and save the encrypted key with RSA."""
        if not os.path.exists(self.aes_key_file):
            print("Error: AES key not found. Please generate an AES key first.")
            return

        with open(self.aes_key_file, 'rb') as key_file:
            aes_key = key_file.read()

        encrypted_aes_key = self.rsa_encrypt(aes_key)
        if not encrypted_aes_key:
            return

        with open(self.aes_encrypted_key_file, 'wb') as key_file:
            key_file.write(encrypted_aes_key)

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        encrypted_message = iv + encryptor.update(padded_data) + encryptor.finalize()

        with open(self.aes_encrypted_file, 'wb') as enc_file:
            enc_file.write(encrypted_message)

        print(f"Message encrypted with AES and saved to {self.aes_encrypted_file}")

    def aes_decrypt_message(self):
        """Decrypt a message using AES and the RSA-decrypted AES key."""
        if not os.path.exists(self.aes_encrypted_key_file):
            print("Error: Encrypted AES key file not found.")
            return

        if not os.path.exists(self.aes_encrypted_file):
            print("Error: AES encrypted file not found.")
            return

        with open(self.aes_encrypted_key_file, 'rb') as key_file:
            encrypted_aes_key = key_file.read()

        aes_key = self.rsa_decrypt(encrypted_aes_key)
        if not aes_key:
            return

        with open(self.aes_encrypted_file, 'rb') as enc_file:
            encrypted_message = enc_file.read()

        iv = encrypted_message[:16]  # Extract the initialization vector
        ciphertext = encrypted_message[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(padded_data) + unpadder.finalize()

        with open(self.aes_decrypted_file, 'w') as dec_file:
            dec_file.write(decrypted_message.decode())

        print(f"Message decrypted with AES and saved to {self.aes_decrypted_file}")

    def interactive_menu(self):
        """Provide an interactive menu for the user."""
        while True:
            print("\n--- Encryption Tool by ybouanan ---")
            print("1. Generate RSA Keys")
            print("2. Encrypt a Message with RSA")
            print("3. Decrypt a Message with RSA")
            print("4. Generate AES Key")
            print("5. Encrypt a Message with AES")
            print("6. Decrypt a Message with AES")
            print("7. Exit")

            choice = input("Enter your choice: ")

            if choice == '1':
                self.generate_rsa_keys()
            elif choice == '2':
                message = input("Enter the message to encrypt with RSA: ")
                encrypted_message = self.rsa_encrypt(message.encode())
                if encrypted_message:
                    with open(self.encrypted_file, 'wb') as enc_file:
                        enc_file.write(encrypted_message)
                    print(f"Message encrypted with RSA and saved to {self.encrypted_file}")
            elif choice == '3':
                if not os.path.exists(self.encrypted_file):
                    print("Error: Encrypted file not found.")
                else:
                    with open(self.encrypted_file, 'rb') as enc_file:
                        encrypted_message = enc_file.read()
                    decrypted_message = self.rsa_decrypt(encrypted_message)
                    if decrypted_message:
                        with open(self.decrypted_file, 'w') as dec_file:
                            dec_file.write(decrypted_message.decode())
                        print(f"Message decrypted with RSA and saved to {self.decrypted_file}")
            elif choice == '4':
                self.generate_aes_key()
            elif choice == '5':
                message = input("Enter the message to encrypt with AES: ")
                self.aes_encrypt_message(message)
            elif choice == '6':
                self.aes_decrypt_message()
            elif choice == '7':
                print("Exiting Encryption Tool. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    tool = EncryptionTool()
    tool.interactive_menu()
