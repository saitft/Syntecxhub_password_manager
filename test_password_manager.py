"""
Unit tests for password manager components.
"""

import unittest
import tempfile
import shutil
import json
from pathlib import Path
from encryption import EncryptionManager
from storage import PasswordStorage


class TestEncryptionManager(unittest.TestCase):
    """Test encryption and decryption functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = EncryptionManager()
    
    def test_key_derivation(self):
        """Test that key derivation produces consistent results."""
        password = "test_password_123"
        salt = b"fixed_salt_16byt"
        
        key1, _ = self.manager.derive_key(password, salt)
        key2, _ = self.manager.derive_key(password, salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), self.manager.KEY_LENGTH)
    
    def test_different_salts_produce_different_keys(self):
        """Test that different salts produce different keys."""
        password = "test_password"
        key1, salt1 = self.manager.derive_key(password)
        key2, salt2 = self.manager.derive_key(password)
        
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(salt1, salt2)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test that data can be encrypted and decrypted."""
        password = "secure_password_123"
        data = {
            'service': 'Gmail',
            'username': 'user@gmail.com',
            'password': 'secret123'
        }
        
        encrypted = self.manager.encrypt(data, password)
        
        self.assertIn('ciphertext', encrypted)
        self.assertIn('salt', encrypted)
        self.assertIn('nonce', encrypted)
        
        decrypted = self.manager.decrypt(encrypted, password)
        self.assertEqual(decrypted, data)
    
    def test_wrong_password_fails(self):
        """Test that decryption fails with wrong password."""
        password = "correct_password"
        data = {'test': 'data'}
        
        encrypted = self.manager.encrypt(data, password)
        
        with self.assertRaises(ValueError):
            self.manager.decrypt(encrypted, "wrong_password")
    
    def test_encrypt_multiple_entries(self):
        """Test encrypting multiple entries in one object."""
        password = "password"
        data = {
            'gmail': {'username': 'user1@gmail.com', 'password': 'pass1'},
            'github': {'username': 'user2', 'password': 'pass2'},
            'twitter': {'username': 'user3', 'password': 'pass3'}
        }
        
        encrypted = self.manager.encrypt(data, password)
        decrypted = self.manager.decrypt(encrypted, password)
        
        self.assertEqual(decrypted, data)


class TestPasswordStorage(unittest.TestCase):
    """Test password storage functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.storage = PasswordStorage(
            storage_file="test.enc",
            data_dir=self.test_dir
        )
        self.master_password = "SecurePassword123!"
    
    def tearDown(self):
        """Clean up test directories."""
        shutil.rmtree(self.test_dir)
    
    def test_set_master_password(self):
        """Test setting master password."""
        self.storage.set_master_password(self.master_password)
        self.assertTrue(self.storage.master_password_hash_file.exists())
    
    def test_master_password_too_short(self):
        """Test that short passwords are rejected."""
        with self.assertRaises(ValueError):
            self.storage.set_master_password("short")
    
    def test_verify_correct_password(self):
        """Test verifying correct master password."""
        self.storage.set_master_password(self.master_password)
        self.assertTrue(self.storage.verify_master_password(self.master_password))
    
    def test_verify_incorrect_password(self):
        """Test verifying incorrect master password."""
        self.storage.set_master_password(self.master_password)
        self.assertFalse(self.storage.verify_master_password("WrongPassword123"))
    
    def test_add_entry(self):
        """Test adding a password entry."""
        self.storage.set_master_password(self.master_password)
        
        self.storage.add_entry(
            service="Gmail",
            username="user@gmail.com",
            password="secret_password",
            master_password=self.master_password,
            url="https://gmail.com"
        )
        
        entry = self.storage.get_entry("Gmail", self.master_password)
        self.assertIsNotNone(entry)
        self.assertEqual(entry['username'], "user@gmail.com")
        self.assertEqual(entry['password'], "secret_password")
    
    def test_get_nonexistent_entry(self):
        """Test getting an entry that doesn't exist."""
        self.storage.set_master_password(self.master_password)
        
        entry = self.storage.get_entry("NonExistent", self.master_password)
        self.assertIsNone(entry)
    
    def test_add_entry_wrong_password(self):
        """Test that adding entry fails with wrong password."""
        self.storage.set_master_password(self.master_password)
        
        with self.assertRaises(ValueError):
            self.storage.add_entry(
                service="Gmail",
                username="user@gmail.com",
                password="secret",
                master_password="WrongPassword"
            )
    
    def test_update_entry(self):
        """Test updating an entry."""
        self.storage.set_master_password(self.master_password)
        
        self.storage.add_entry(
            service="Github",
            username="olduser",
            password="oldpass",
            master_password=self.master_password
        )
        
        self.storage.update_entry(
            service="Github",
            master_password=self.master_password,
            username="newuser",
            password="newpass"
        )
        
        entry = self.storage.get_entry("Github", self.master_password)
        self.assertEqual(entry['username'], "newuser")
        self.assertEqual(entry['password'], "newpass")
    
    def test_delete_entry(self):
        """Test deleting an entry."""
        self.storage.set_master_password(self.master_password)
        
        self.storage.add_entry(
            service="Twitter",
            username="twitteruser",
            password="twitterpass",
            master_password=self.master_password
        )
        
        deleted = self.storage.delete_entry("Twitter", self.master_password)
        self.assertTrue(deleted)
        
        entry = self.storage.get_entry("Twitter", self.master_password)
        self.assertIsNone(entry)
    
    def test_delete_nonexistent_entry(self):
        """Test deleting an entry that doesn't exist."""
        self.storage.set_master_password(self.master_password)
        
        deleted = self.storage.delete_entry("NonExistent", self.master_password)
        self.assertFalse(deleted)
    
    def test_search_entries(self):
        """Test searching entries."""
        self.storage.set_master_password(self.master_password)
        
        self.storage.add_entry("Gmail", "gmail_user", "pass1", self.master_password)
        self.storage.add_entry("GitHub", "github_user", "pass2", self.master_password)
        self.storage.add_entry("GitLab", "gitlab_user", "pass3", self.master_password)
        
        results = self.storage.search_entries("git", self.master_password)
        self.assertEqual(len(results), 2)
        
        results = self.storage.search_entries("mail", self.master_password)
        self.assertEqual(len(results), 1)
    
    def test_search_case_insensitive(self):
        """Test that search is case-insensitive."""
        self.storage.set_master_password(self.master_password)
        self.storage.add_entry("Gmail", "gmail_user", "pass", self.master_password)
        
        results1 = self.storage.search_entries("GMAIL", self.master_password)
        results2 = self.storage.search_entries("gmail", self.master_password)
        
        self.assertEqual(len(results1), len(results2))
    
    def test_list_all_entries_excludes_passwords(self):
        """Test that list_all_entries doesn't return passwords."""
        self.storage.set_master_password(self.master_password)
        
        self.storage.add_entry("Gmail", "user@gmail.com", "secret123", self.master_password)
        
        entries = self.storage.list_all_entries(self.master_password)
        
        self.assertEqual(len(entries), 1)
        self.assertNotIn('password', entries[0])
        self.assertEqual(entries[0]['service'], 'Gmail')
    
    def test_persistence(self):
        """Test that data persists across storage instances."""
        self.storage.set_master_password(self.master_password)
        
        self.storage.add_entry(
            service="Persistent",
            username="persistent_user",
            password="persistent_pass",
            master_password=self.master_password
        )
        
        # Create new storage instance pointing to same file
        storage2 = PasswordStorage(
            storage_file="test.enc",
            data_dir=self.test_dir
        )
        
        entry = storage2.get_entry("Persistent", self.master_password)
        self.assertIsNotNone(entry)
        self.assertEqual(entry['username'], "persistent_user")


if __name__ == '__main__':
    unittest.main()
