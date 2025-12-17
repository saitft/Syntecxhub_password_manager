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
├── password_manager.py      # Main CLI application
├── encryption.py            # AES-256-GCM encryption/decryption
├── storage.py               # Encrypted JSON storage management
├── examples.py              # Usage examples
├── test_password_manager.py # Unit tests
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── passwords.enc           # Encrypted password database (auto-created)
```

## Security Best Practices

1. **Master Password**: Choose a strong, unique master password (minimum 8 characters, mix of upper/lowercase, numbers, symbols recommended)
2. **File Permissions**: The encrypted database file is created with permissions 600 (owner read/write only)
3. **No Backups Without Encryption**: Always keep encrypted backups of your password database
4. **Regular Updates**: Keep Python and dependencies updated for security patches
5. **Local Storage Only**: All passwords remain on your local machine - no cloud sync

## How It Works

### Encryption Process

1. Master password → PBKDF2-SHA256 key derivation (480,000 iterations)
2. Each password entry encrypted with AES-256-GCM
3. Nonce + ciphertext + auth tag stored in encrypted JSON file
4. File permissions set to 600 (owner read/write only)

### Decryption Process

1. Master password verified using SHA-256 hash
2. Derived key regenerated using same parameters
3. Each entry decrypted and verified using authentication tag
4. Original password recovered and displayed

## Dependencies

- `cryptography` - AES-256-GCM encryption, PBKDF2, secure random
- `pydantic` - Data validation
- `python-dotenv` - Environment variable management (optional)

## Examples

### Programmatic Usage

```python
from password_manager import PasswordManager

# Initialize
pm = PasswordManager()

# Set master password (first time)
pm.set_master_password("MySecurePassword123!")

# Add a password
pm.add_password(
    service="Gmail",
    username="user@gmail.com",
    password="SecurePass123!",
    url="https://gmail.com",
    notes="Work email"
)

# Retrieve a password
entry = pm.get_password("Gmail")
print(f"Username: {entry['username']}")
print(f"Password: {entry['password']}")

# Search passwords
results = pm.search_password("mail")
for entry in results:
    print(f"- {entry['service']}: {entry['username']}")

# Update a password
pm.update_password("Gmail", password="NewPassword456!")

# Delete a password
pm.delete_password("Gmail")
```

## Testing

Run the test suite:

```bash
python -m pytest test_password_manager.py -v
```

## Troubleshooting

### "File not found" error

- The encrypted database will be created automatically on first run

### "Invalid master password" error

- Ensure you're entering the correct master password
- Master password is case-sensitive

### Permission denied error

- Check that you have read/write permissions in the application directory

## License

MIT License - Feel free to use and modify

## Disclaimer

This password manager is provided as-is for educational and personal use. While security best practices are implemented, no security tool is 100% foolproof. Always maintain secure backups and use strong master passwords.
