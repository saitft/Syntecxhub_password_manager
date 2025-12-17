"""
Example usage of the password manager library.
Shows how to use the PasswordStorage and EncryptionManager classes.
"""

from storage import PasswordStorage
from encryption import EncryptionManager

# Example 1: Using the PasswordStorage class
def example_storage():
    print("=" * 60)
    print("EXAMPLE 1: PasswordStorage Usage")
    print("=" * 60)
    
    # Initialize storage
    storage = PasswordStorage()
    
    # Set master password (first time)
    master_password = "SecurePassword123!"
    storage.set_master_password(master_password)
    print("✓ Master password set")
    
    # Add some password entries
    storage.add_entry(
        service="Gmail",
        username="user@gmail.com",
        password="gmail_secret_123",
        url="https://gmail.com",
        notes="Main email account",
        master_password=master_password
    )
    print("✓ Added Gmail entry")
    
    storage.add_entry(
        service="GitHub",
        username="myusername",
        password="github_token_xyz",
        url="https://github.com",
        notes="Personal GitHub account",
        master_password=master_password
    )
    print("✓ Added GitHub entry")
    
    storage.add_entry(
        service="AWS",
        username="aws_user",
        password="aws_secret_key",
        notes="AWS root credentials",
        master_password=master_password
    )
    print("✓ Added AWS entry")
    
    # Retrieve a password
    print("\n--- Retrieving Gmail password ---")
    gmail_entry = storage.get_entry("Gmail", master_password)
    print(f"Service: {gmail_entry['service']}")
    print(f"Username: {gmail_entry['username']}")
    print(f"Password: {gmail_entry['password']}")
    print(f"URL: {gmail_entry['url']}")
    
    # Update a password
    print("\n--- Updating AWS password ---")
    storage.update_entry(
        service="AWS",
        password="aws_new_secret_key_123",
        master_password=master_password
    )
    print("✓ Password updated")
    
    # Search entries
    print("\n--- Searching for 'git' ---")
    results = storage.search_entries("git", master_password)
    for result in results:
        print(f"  - {result['service']}: {result['username']}")
    
    # List all entries (without passwords)
    print("\n--- All stored entries ---")
    all_entries = storage.list_all_entries(master_password)
    for i, entry in enumerate(all_entries, 1):
        print(f"{i}. {entry['service']} ({entry['username']})")
    
    # Delete an entry
    print("\n--- Deleting AWS entry ---")
    storage.delete_entry("AWS", master_password)
    print("✓ Entry deleted")
    
    print("\n--- All entries after deletion ---")
    all_entries = storage.list_all_entries(master_password)
    for i, entry in enumerate(all_entries, 1):
        print(f"{i}. {entry['service']} ({entry['username']})")


# Example 2: Using the EncryptionManager directly
def example_encryption():
    print("\n" + "=" * 60)
    print("EXAMPLE 2: EncryptionManager Usage")
    print("=" * 60)
    
    manager = EncryptionManager()
    
    # Data to encrypt
    sensitive_data = {
        'username': 'user@example.com',
        'password': 'super_secret_123',
        'api_key': 'sk_live_abc123xyz789',
        'token': 'refresh_token_here'
    }
    
    master_password = "MySecurePassword123!"
    
    # Encrypt data
    print("\n--- Encrypting data ---")
    encrypted = manager.encrypt(sensitive_data, master_password)
    
    print(f"Ciphertext: {encrypted['ciphertext'][:50]}...")
    print(f"Salt: {encrypted['salt']}")
    print(f"Nonce: {encrypted['nonce']}")
    
    # Decrypt data
    print("\n--- Decrypting data ---")
    decrypted = manager.decrypt(encrypted, master_password)
    
    print("Decrypted successfully!")
    for key, value in decrypted.items():
        print(f"  {key}: {value}")
    
    # Try with wrong password
    print("\n--- Attempting decryption with wrong password ---")
    try:
        manager.decrypt(encrypted, "WrongPassword")
    except ValueError as e:
        print(f"✓ Correctly rejected: {e}")


# Example 3: Error handling
def example_error_handling():
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Error Handling")
    print("=" * 60)
    
    storage = PasswordStorage()
    master_password = "SecurePassword123!"
    
    storage.set_master_password(master_password)
    
    # Add an entry
    storage.add_entry(
        service="Example",
        username="user",
        password="pass",
        master_password=master_password
    )
    
    # Try operations with wrong password
    print("\n--- Testing wrong password ---")
    try:
        storage.get_entry("Example", "WrongPassword")
    except ValueError as e:
        print(f"✓ Correctly rejected: {e}")
    
    # Try to add duplicate
    print("\n--- Testing duplicate entry ---")
    try:
        storage.add_entry(
            service="Example",
            username="user2",
            password="pass2",
            master_password=master_password
        )
    except Exception as e:
        print(f"Note: Duplicate handling - entry already exists (use update)")
    
    # Try to update non-existent entry
    print("\n--- Testing non-existent entry update ---")
    try:
        storage.update_entry(
            service="NonExistent",
            password="newpass",
            master_password=master_password
        )
    except ValueError as e:
        print(f"✓ Correctly rejected: {e}")
    
    # Delete non-existent entry
    print("\n--- Testing non-existent entry deletion ---")
    deleted = storage.delete_entry("NonExistent", master_password)
    print(f"Deleted: {deleted} (returns False if not found)")


if __name__ == "__main__":
    # Run all examples
    example_storage()
    example_encryption()
    example_error_handling()
    
    print("\n" + "=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)
