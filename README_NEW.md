# Syntecxhub Password Manager

A secure, local password manager that stores credentials encrypted on disk using AES-256-GCM encryption with master password protection.

## Features

✓ **Strong Encryption**: AES-256-GCM with authenticated encryption
✓ **Secure Key Derivation**: PBKDF2-SHA256 with 480,000 iterations (NIST 2024 recommendation)
✓ **Master Password**: Protects all stored passwords
✓ **Encrypted Storage**: All data saved as encrypted JSON on disk
✓ **Password Operations**: Add, retrieve, update, delete, and search passwords
✓ **File Permissions**: Secure file permissions (600 - owner read/write only)
✓ **CLI Interface**: User-friendly command-line menu
✓ **No Cloud**: Everything stays local on your machine

## Security Features

- **AES-256-GCM**: Industry-standard authenticated encryption (prevents tampering)
- **PBKDF2-SHA256**: 480,000 iterations for key derivation (resistant to brute force attacks)
- **Random Nonces**: Each encryption uses a unique nonce (prevents replay attacks)
- **Authentication Tags**: Verifies data integrity and authenticity
- **Secure File Permissions**: Encrypted files readable only by owner
- **Master Password Hashing**: Passwords verified using SHA-256 hashing

## Installation

1. **Clone or download** the repository
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Quick Start

Run the password manager:

```bash
python password_manager.py
```

### First Time Setup

When you run the application for the first time:

1. You'll be prompted to set a master password (minimum 8 characters)
2. Confirm your master password
3. Your encrypted storage is created

### Main Operations

#### 1. Add a Password

```
Option: 1
Service name: Gmail
Username/Email: user@gmail.com
Password: (hidden input)
URL (optional): https://gmail.com
Notes (optional): Main work email
```

#### 2. Retrieve a Password

```
Option: 2
Service name: Gmail
→ Displays: Service, Username, Password, URL, Notes
```

#### 3. Update a Password

```
Option: 3
Service name: Gmail
→ Update any field as needed
```

#### 4. Delete a Password

```
Option: 4
Service name: Gmail
→ Confirm deletion
```

#### 5. Search Passwords

```
Option: 5
Search query: gmail
→ Lists all matching entries
```

#### 6. List All Entries

```
Option: 6
→ Displays all entries (without passwords for safety)
```

## File Structure

```
Syntecxhub_password_manager/
├── password_manager.py       # Main CLI application
├── storage.py                # Password storage and operations
├── encryption.py             # Encryption/decryption utilities
├── test_password_manager.py  # Unit tests
├── requirements.txt          # Python dependencies
└── .password_manager/        # Created automatically
    ├── passwords.enc         # Encrypted password database
    └── master_hash           # Master password hash (for verification)
```

## Encrypted Storage Format

Passwords are stored in `.password_manager/passwords.enc` with the following structure:

```json
{
  "ciphertext": "hex_encoded_encrypted_data",
  "salt": "hex_encoded_salt",
  "nonce": "hex_encoded_nonce"
}
```

The actual password data (once decrypted) looks like:

```json
{
  "gmail": {
    "service": "Gmail",
    "username": "user@gmail.com",
    "password": "secret123",
    "url": "https://gmail.com",
    "notes": "Main work email"
  },
  "github": {
    "service": "GitHub",
    "username": "myusername",
    "password": "github_token_123",
    "url": "https://github.com",
    "notes": "Personal account"
  }
}
```

## Python API Usage

You can also use the password manager programmatically:

### Basic Usage

```python
from storage import PasswordStorage

# Create storage instance
storage = PasswordStorage()

# Set master password (first time only)
storage.set_master_password("MySecurePassword123!")

# Add a password entry
storage.add_entry(
    service="Gmail",
    username="user@gmail.com",
    password="secret123",
    url="https://gmail.com",
    notes="Main email account",
    master_password="MySecurePassword123!"
)

# Retrieve a password
entry = storage.get_entry("Gmail", "MySecurePassword123!")
print(entry['password'])  # Output: secret123

# Update a password
storage.update_entry(
    service="Gmail",
    password="new_password_123",
    master_password="MySecurePassword123!"
)

# Search passwords
results = storage.search_entries("gmail", "MySecurePassword123!")
for result in results:
    print(result['service'], result['username'])

# Delete a password
storage.delete_entry("Gmail", "MySecurePassword123!")

# List all entries (without passwords)
all_entries = storage.list_all_entries("MySecurePassword123!")
```

### Encryption API

```python
from encryption import EncryptionManager

manager = EncryptionManager()

# Encrypt data
data = {'username': 'user@example.com', 'password': 'secret123'}
encrypted = manager.encrypt(data, "MyMasterPassword")

# Decrypt data
decrypted = manager.decrypt(encrypted, "MyMasterPassword")
```

## Running Tests

Execute the comprehensive test suite:

```bash
python -m unittest test_password_manager.py -v
```

### Test Coverage

- ✓ Key derivation consistency
- ✓ Encryption/decryption roundtrips
- ✓ Wrong password handling
- ✓ Master password verification
- ✓ Add/update/delete operations
- ✓ Search functionality (case-insensitive)
- ✓ Data persistence across sessions
- ✓ Secure file permissions

## Security Best Practices

1. **Master Password**:

   - Use at least 12 characters
   - Mix uppercase, lowercase, numbers, and symbols
   - Avoid dictionary words

2. **Storage Location**:

   - `.password_manager/` directory is created in your project folder
   - Keep your project directory secure
   - Don't commit `.password_manager/` to version control

3. **Backing Up**:

   - Regular backups of `.password_manager/` directory
   - Backups are encrypted and only decryptable with master password
   - Consider encryption for backup storage too

4. **Master Password Recovery**:
   - There is NO master password recovery mechanism
   - If you forget your master password, all passwords are lost
   - Write it down in a safe place

## Technical Details

### Encryption Scheme

- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **Mode**: Authenticated encryption (prevents tampering)
- **Key Size**: 256 bits
- **Authentication Tag**: 128 bits

### Key Derivation

- **Function**: PBKDF2-SHA256
- **Iterations**: 480,000 (NIST 2024 recommendation)
- **Salt Length**: 128 bits
- **Output**: 256 bits

### Master Password Storage

- Master password is **never stored**
- Only SHA-256 hash is stored for verification
- Hash cannot be reversed to get password

## Troubleshooting

**"Incorrect master password" on startup?**

- Master password is case-sensitive
- Verify CAPS LOCK is off
- Recreate `.password_manager/` if files are corrupted

**"Decryption failed" error?**

- Wrong master password
- Corrupted encrypted file
- The password database may have been modified externally

**Forgot master password?**

- There is no recovery - delete `.password_manager/` folder to start fresh
- All passwords will be lost

## Dependencies

- **cryptography**: For AES-256-GCM encryption and PBKDF2 key derivation

## License

This project is provided as-is for educational and personal use.

## Contributing

Contributions welcome! Areas for enhancement:

- Password strength meter
- Password generation utility
- Import/export functionality
- Multi-user support
- Backup and restore utilities
- Cross-platform GUI

## Disclaimer

This password manager is for personal use. While it uses industry-standard encryption, always:

- Keep your master password secure
- Regularly back up your `.password_manager/` folder
- Test recovery procedures

---

**Built with security in mind** 🔐
