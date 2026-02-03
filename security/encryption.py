"""
ConnectU Security Module
Encryption and Key Exchange Implementation
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets


class EncryptionService:
    """Handles encryption, decryption, and key exchange"""
    
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """
        Generate RSA key pair for user
        Returns: (public_key_pem, private_key_pem)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Can add password encryption here
        )
        
        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem.decode('utf-8'), private_pem.decode('utf-8')
    
    @staticmethod
    def encrypt_with_rsa(public_key_pem, data):
        """
        Encrypt data using RSA public key
        Used for key exchange
        """
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Encrypt data
        encrypted = public_key.encrypt(
            data if isinstance(data, bytes) else data.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return base64 encoded
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_with_rsa(private_key_pem, encrypted_data):
        """
        Decrypt data using RSA private key
        Used for basic data exchange (returns string)
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Decrypt data
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode('utf-8')

    @staticmethod
    def decrypt_key_with_rsa(private_key_pem, encrypted_data):
        """
        Decrypt a cryptographic key using RSA private key
        Returns raw bytes (not decoded string)
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Decrypt data
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted_bytes

    
    @staticmethod
    def generate_aes_key():
        """Generate AES-256 key (32 bytes)"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def encrypt_with_aes(key, plaintext):
        """
        Encrypt data using AES-256-GCM
        Returns: (ciphertext, iv, auth_tag)
        """
        # Generate random IV (initialization vector)
        iv = os.urandom(12)  # 96 bits for GCM
        
        # Create AESGCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt (GCM mode provides both encryption and authentication)
        ciphertext = aesgcm.encrypt(
            iv,
            plaintext if isinstance(plaintext, bytes) else plaintext.encode('utf-8'),
            None  # No additional authenticated data
        )
        
        # GCM ciphertext includes the tag at the end (16 bytes)
        tag = ciphertext[-16:]
        encrypted_data = ciphertext[:-16]
        
        # Return base64 encoded values
        return (
            base64.b64encode(encrypted_data).decode('utf-8'),
            base64.b64encode(iv).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8')
        )

    
    @staticmethod
    def decrypt_with_aes(key, ciphertext, iv, auth_tag=None):
        """
        Decrypt data using AES-256-GCM
        """
        # Decode base64
        ciphertext_bytes = base64.b64decode(ciphertext)
        iv_bytes = base64.b64decode(iv)
        
        # Reconstruct ciphertext + tag if tag provided separately
        if auth_tag:
            tag_bytes = base64.b64decode(auth_tag)
            full_ciphertext = ciphertext_bytes + tag_bytes
        else:
            full_ciphertext = ciphertext_bytes
            
        # Create AESGCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt
        plaintext = aesgcm.decrypt(
            iv_bytes,
            full_ciphertext,
            None
        )
        
        return plaintext.decode('utf-8')

    
    @staticmethod
    def encrypt_message_hybrid(receiver_public_key_pem, message, sender_public_key_pem=None):
        """
        Hybrid encryption: RSA for key exchange + AES for message
        
        Process:
        1. Generate random AES key
        2. Encrypt message with AES key
        3. Encrypt AES key with receiver's RSA public key
        4. (Optional) Encrypt AES key with sender's RSA public key
        
        Returns: dict with encrypted_content, encrypted_key, iv, auth_tag, and optional sender_encrypted_key
        """
        # Generate AES key
        aes_key = EncryptionService.generate_aes_key()
        
        # Encrypt message with AES
        encrypted_content, iv, auth_tag = EncryptionService.encrypt_with_aes(aes_key, message)
        
        # Encrypt AES key with receiver's RSA public key
        encrypted_key = EncryptionService.encrypt_with_rsa(
            receiver_public_key_pem,
            aes_key
        )
        
        result = {
            'encrypted_content': encrypted_content,
            'encrypted_key': encrypted_key,
            'iv': iv,
            'auth_tag': auth_tag
        }
        
        # Encrypt AES key with sender's RSA public key if provided
        if sender_public_key_pem:
            result['sender_encrypted_key'] = EncryptionService.encrypt_with_rsa(
                sender_public_key_pem,
                aes_key
            )
            
        return result

    
    @staticmethod
    def decrypt_message_hybrid(receiver_private_key_pem, encrypted_data):
        """
        Decrypt hybrid encrypted message
        
        Args:
            encrypted_data: dict with encrypted_content, encrypted_key, iv
        
        Returns: decrypted message
        """
        # Decrypt AES key using receiver's RSA private key
        aes_key = EncryptionService.decrypt_with_rsa(
            receiver_private_key_pem,
            encrypted_data['encrypted_key']
        )
        
        # Decrypt message with AES key
        message = EncryptionService.decrypt_with_aes(
            aes_key.encode('utf-8') if isinstance(aes_key, str) else aes_key,
            encrypted_data['encrypted_content'],
            encrypted_data['iv'],
            encrypted_data.get('auth_tag')
        )
        
        return message

    
    @staticmethod
    def encrypt_private_key(private_key_pem, password):
        """
        Encrypt private key with password for storage
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Serialize with encryption
        encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )
        
        return encrypted_pem.decode('utf-8')
    
    @staticmethod
    def decrypt_private_key(encrypted_private_key_pem, password):
        """
        Decrypt private key with password
        """
        # Load and decrypt private key
        private_key = serialization.load_pem_private_key(
            encrypted_private_key_pem.encode('utf-8'),
            password=password.encode('utf-8'),
            backend=default_backend()
        )
        
        # Serialize without encryption
        decrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return decrypted_pem.decode('utf-8')
