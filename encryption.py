"""
Encryption module for secure password storage.
Uses AES-256-GCM for authenticated encryption and PBKDF2 for key derivation.
"""

import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class EncryptionManager:
    """Handles encryption and decryption of sensitive data."""
    
    # Constants for key derivation and encryption
    KEY_LENGTH = 32  # 256 bits for AES-256
    SALT_LENGTH = 16  # 128 bits
    ITERATIONS = 480000  # PBKDF2 iterations (NIST recommendation for 2024)
    NONCE_LENGTH = 12  # 96 bits for GCM
    TAG_LENGTH = 16  # 128 bits for authentication tag
    
    @staticmethod
    def derive_key(master_password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive a cryptographic key from master password using PBKDF2-SHA256.
        
        Args:
            master_password: The master password string
            salt: Optional salt (if None, generates new random salt)
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(EncryptionManager.SALT_LENGTH)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=EncryptionManager.KEY_LENGTH,
            salt=salt,
            iterations=EncryptionManager.ITERATIONS,
            backend=default_backend()
        )
        
        key = kdf.derive(master_password.encode())
        return key, salt
    
    @staticmethod
    def encrypt(data: dict, master_password: str, salt: bytes = None) -> dict:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Dictionary to encrypt (will be JSON serialized)
            master_password: Master password for key derivation
            salt: Optional salt for key derivation
            
        Returns:
            Dictionary containing 'ciphertext', 'salt', 'nonce' (all hex encoded)
        """
        key, salt = EncryptionManager.derive_key(master_password, salt)
        
        # Generate random nonce for this encryption
        nonce = os.urandom(EncryptionManager.NONCE_LENGTH)
        
        # Serialize data to JSON
        plaintext = json.dumps(data).encode()
        
        # Encrypt using AES-256-GCM
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        # Return encrypted data with metadata
        return {
            'ciphertext': ciphertext.hex(),
            'salt': salt.hex(),
            'nonce': nonce.hex()
        }
    
    @staticmethod
    def decrypt(encrypted_data: dict, master_password: str) -> dict:
        """
        Decrypt data encrypted with AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary with 'ciphertext', 'salt', 'nonce' (hex encoded)
            master_password: Master password for key derivation
            
        Returns:
            Decrypted dictionary
            
        Raises:
            ValueError: If decryption fails (wrong password or corrupted data)
        """
        try:
            # Convert hex strings back to bytes
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            salt = bytes.fromhex(encrypted_data['salt'])
            nonce = bytes.fromhex(encrypted_data['nonce'])
            
            # Derive key using stored salt
            key, _ = EncryptionManager.derive_key(master_password, salt)
            
            # Decrypt using AES-256-GCM
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            
            # Deserialize JSON
            return json.loads(plaintext.decode())
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}. Wrong master password?")
