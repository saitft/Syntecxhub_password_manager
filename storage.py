"""
Secure password storage module.
Manages encrypted JSON file storage and master password verification.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional, List, Dict
from encryption import EncryptionManager


class PasswordStorage:
    """Handles encrypted password storage and operations."""
    
    def __init__(self, storage_file: str = "passwords.enc", data_dir: str = ".password_manager"):
        """
        Initialize password storage.
        
        Args:
            storage_file: Name of encrypted storage file
            data_dir: Directory to store encrypted data (default: .password_manager)
        """
        self.data_dir = Path(data_dir)
        self.storage_file = self.data_dir / storage_file
        self.master_password_hash_file = self.data_dir / "master_hash"
        
        # Create data directory if it doesn't exist
        self.data_dir.mkdir(exist_ok=True, mode=0o700)  # rwx only for owner
        
        self._encryption_manager = EncryptionManager()
    
    def _hash_master_password(self, password: str) -> str:
        """Hash master password using SHA-256 for verification."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def set_master_password(self, password: str) -> None:
        """
        Set or reset master password.
        
        Args:
            password: New master password
        """
        if len(password) < 8:
            raise ValueError("Master password must be at least 8 characters long")
        
        password_hash = self._hash_master_password(password)
        
        # Store hash for verification
        with open(self.master_password_hash_file, 'w') as f:
            f.write(password_hash)
        os.chmod(self.master_password_hash_file, 0o600)  # rw only for owner
        
        # Initialize empty encrypted storage
        self._save_encrypted_entries({}, password)
    
    def verify_master_password(self, password: str) -> bool:
        """
        Verify that the provided master password is correct.
        
        Args:
            password: Master password to verify
            
        Returns:
            True if password is correct
        """
        if not self.master_password_hash_file.exists():
            return False
        
        with open(self.master_password_hash_file, 'r') as f:
            stored_hash = f.read().strip()
        
        provided_hash = self._hash_master_password(password)
        return provided_hash == stored_hash
    
    def _load_encrypted_entries(self, master_password: str) -> dict:
        """
        Load and decrypt password entries from storage.
        
        Args:
            master_password: Master password for decryption
            
        Returns:
            Dictionary of password entries
        """
        if not self.storage_file.exists():
            return {}
        
        try:
            with open(self.storage_file, 'r') as f:
                encrypted_data = json.load(f)
            
            return self._encryption_manager.decrypt(encrypted_data, master_password)
        except FileNotFoundError:
            return {}
    
    def _save_encrypted_entries(self, entries: dict, master_password: str) -> None:
        """
        Encrypt and save password entries to storage.
        
        Args:
            entries: Dictionary of password entries
            master_password: Master password for encryption
        """
        encrypted_data = self._encryption_manager.encrypt(entries, master_password)
        
        with open(self.storage_file, 'w') as f:
            json.dump(encrypted_data, f)
        os.chmod(self.storage_file, 0o600)  # rw only for owner
    
    def add_entry(self, service: str, username: str, password: str, 
                  master_password: str, url: str = "", notes: str = "") -> None:
        """
        Add a new password entry.
        
        Args:
            service: Service/website name
            username: Username or email
            password: Password to store
            master_password: Master password for access
            url: Optional URL for the service
            notes: Optional additional notes
        """
        if not self.verify_master_password(master_password):
            raise ValueError("Incorrect master password")
        
        entries = self._load_encrypted_entries(master_password)
        
        # Use service name as key (lowercase for consistency)
        key = service.lower()
        
        entries[key] = {
            'service': service,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes
        }
        
        self._save_encrypted_entries(entries, master_password)
    
    def get_entry(self, service: str, master_password: str) -> Optional[dict]:
        """
        Retrieve a password entry.
        
        Args:
            service: Service name
            master_password: Master password for access
            
        Returns:
            Entry dictionary or None if not found
        """
        if not self.verify_master_password(master_password):
            raise ValueError("Incorrect master password")
        
        entries = self._load_encrypted_entries(master_password)
        return entries.get(service.lower())
    
    def update_entry(self, service: str, master_password: str, 
                    username: str = None, password: str = None, 
                    url: str = None, notes: str = None) -> None:
        """
        Update an existing password entry.
        
        Args:
            service: Service name
            master_password: Master password for access
            username: New username (optional)
            password: New password (optional)
            url: New URL (optional)
            notes: New notes (optional)
        """
        if not self.verify_master_password(master_password):
            raise ValueError("Incorrect master password")
        
        entries = self._load_encrypted_entries(master_password)
        key = service.lower()
        
        if key not in entries:
            raise ValueError(f"Service '{service}' not found")
        
        # Update fields if provided
        if username is not None:
            entries[key]['username'] = username
        if password is not None:
            entries[key]['password'] = password
        if url is not None:
            entries[key]['url'] = url
        if notes is not None:
            entries[key]['notes'] = notes
        
        self._save_encrypted_entries(entries, master_password)
    
    def delete_entry(self, service: str, master_password: str) -> bool:
        """
        Delete a password entry.
        
        Args:
            service: Service name
            master_password: Master password for access
            
        Returns:
            True if deleted, False if not found
        """
        if not self.verify_master_password(master_password):
            raise ValueError("Incorrect master password")
        
        entries = self._load_encrypted_entries(master_password)
        key = service.lower()
        
        if key in entries:
            del entries[key]
            self._save_encrypted_entries(entries, master_password)
            return True
        
        return False
    
    def search_entries(self, query: str, master_password: str) -> List[dict]:
        """
        Search password entries by service name or username.
        
        Args:
            query: Search query (case-insensitive)
            master_password: Master password for access
            
        Returns:
            List of matching entries
        """
        if not self.verify_master_password(master_password):
            raise ValueError("Incorrect master password")
        
        entries = self._load_encrypted_entries(master_password)
        query_lower = query.lower()
        
        results = []
        for entry in entries.values():
            if (query_lower in entry['service'].lower() or 
                query_lower in entry['username'].lower()):
                results.append(entry)
        
        return results
    
    def list_all_entries(self, master_password: str) -> List[dict]:
        """
        List all password entries.
        
        Args:
            master_password: Master password for access
            
        Returns:
            List of all entries (without passwords for security)
        """
        if not self.verify_master_password(master_password):
            raise ValueError("Incorrect master password")
        
        entries = self._load_encrypted_entries(master_password)
        
        # Return entries without passwords for safety
        result = []
        for entry in entries.values():
            safe_entry = {
                'service': entry['service'],
                'username': entry['username'],
                'url': entry.get('url', ''),
                'notes': entry.get('notes', '')
            }
            result.append(safe_entry)
        
        return result
