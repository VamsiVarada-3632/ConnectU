"""
ConnectU Security Module
Digital Signatures Implementation
"""

import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class SignatureService:
    """Handles digital signatures for data integrity and authenticity"""
    
    @staticmethod
    def hash_content_sha256(content):
        """
        Create SHA-256 hash of content
        Returns: hex digest of hash
        """
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        hash_obj = hashlib.sha256(content)
        return hash_obj.hexdigest()
    
    @staticmethod
    def sign_data(private_key_pem, data):
        """
        Sign data using RSA private key
        
        Process:
        1. Hash the data using SHA-256
        2. Sign the hash using RSA private key
        
        Returns: base64 encoded signature
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Sign the data
        signature = private_key.sign(
            data if isinstance(data, bytes) else data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Return base64 encoded signature
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(public_key_pem, data, signature_b64):
        """
        Verify digital signature using RSA public key
        
        Returns: True if signature is valid, False otherwise
        """
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            public_key.verify(
                signature,
                data if isinstance(data, bytes) else data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
        
        except Exception as e:
            # Signature verification failed
            return False
    
    @staticmethod
    def sign_post(private_key_pem, post_content, image_data=None):
        """
        Sign a post for integrity verification
        
        Returns: (content_hash, signature)
        """
        # Combine content and image for hashing
        combined_data = post_content
        if image_data:
            combined_data += image_data
        
        # Create hash
        content_hash = SignatureService.hash_content_sha256(combined_data)
        
        # Sign the hash
        signature = SignatureService.sign_data(private_key_pem, content_hash)
        
        return content_hash, signature
    
    @staticmethod
    def verify_post(public_key_pem, post_content, image_data, content_hash, signature):
        """
        Verify post signature and integrity
        
        Returns: (is_valid, message)
        """
        # Recreate hash
        combined_data = post_content
        if image_data:
            combined_data += image_data
        
        computed_hash = SignatureService.hash_content_sha256(combined_data)
        
        # Check if content has been tampered with
        if computed_hash != content_hash:
            return False, "Content has been modified (hash mismatch)"
        
        # Verify signature
        is_valid = SignatureService.verify_signature(public_key_pem, content_hash, signature)
        
        if is_valid:
            return True, "Signature is valid - content is authentic"
        else:
            return False, "Invalid signature - content authenticity cannot be verified"
    
    @staticmethod
    def create_message_signature(private_key_pem, message_content):
        """
        Create signature for message (non-repudiation)
        
        Returns: signature
        """
        return SignatureService.sign_data(private_key_pem, message_content)
    
    @staticmethod
    def verify_message_signature(public_key_pem, message_content, signature):
        """
        Verify message signature
        
        Returns: Boolean
        """
        return SignatureService.verify_signature(public_key_pem, message_content, signature)
