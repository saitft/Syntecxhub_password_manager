"""
Command-line interface for the password manager.
Provides interactive menu-driven access to password operations.
"""

import sys
import getpass
from typing import Optional
from storage import PasswordStorage


class PasswordManagerCLI:
    """CLI interface for password manager operations."""
    
    def __init__(self):
        """Initialize the password manager."""
        self.storage = PasswordStorage()
        self.master_password = None
        self.authenticated = False
    
    def print_menu(self):
        """Display main menu."""
        print("\n" + "="*50)
        print("PASSWORD MANAGER")
        print("="*50)
        if self.authenticated:
            print("1. Add new password entry")
            print("2. Retrieve password")
            print("3. Update password entry")
            print("4. Delete password entry")
            print("5. Search passwords")
            print("6. List all entries (no passwords)")
            print("7. Logout")
            print("8. Exit")
        else:
            print("1. Setup master password (first time)")
            print("2. Login")
            print("3. Exit")
        print("="*50)
    
    def setup_master_password(self):
        """Setup new master password."""
        print("\n--- Setup Master Password ---")
        print("This is your first time using the password manager.")
        print("Note: Master password must be at least 8 characters long.")
        
        while True:
            password = getpass.getpass("Enter master password: ")
            
            if len(password) < 8:
                print("❌ Master password must be at least 8 characters long")
                continue
            
            confirm = getpass.getpass("Confirm master password: ")
            
            if password != confirm:
                print("❌ Passwords don't match")
                continue
            
            try:
                self.storage.set_master_password(password)
                self.master_password = password
                self.authenticated = True
                print("✓ Master password set successfully!")
                return
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def login(self):
        """Authenticate with master password."""
        print("\n--- Login ---")
        
        for attempt in range(3):
            password = getpass.getpass("Enter master password: ")
            
            if self.storage.verify_master_password(password):
                self.master_password = password
                self.authenticated = True
                print("✓ Authentication successful!")
                return
            else:
                remaining = 3 - attempt - 1
                print(f"❌ Incorrect password ({remaining} attempts remaining)")
        
        print("❌ Maximum attempts exceeded")
    
    def add_password(self):
        """Add a new password entry."""
        print("\n--- Add New Password Entry ---")
        
        service = input("Service name (e.g., Gmail, GitHub): ").strip()
        if not service:
            print("❌ Service name cannot be empty")
            return
        
        # Check if already exists
        if self.storage.get_entry(service, self.master_password):
            print(f"❌ Entry for '{service}' already exists. Use update to modify.")
            return
        
        username = input("Username/Email: ").strip()
        if not username:
            print("❌ Username cannot be empty")
            return
        
        password = getpass.getpass("Password: ")
        if not password:
            print("❌ Password cannot be empty")
            return
        
        url = input("URL (optional): ").strip()
        notes = input("Notes (optional): ").strip()
        
        try:
            self.storage.add_entry(
                service=service,
                username=username,
                password=password,
                url=url,
                notes=notes,
                master_password=self.master_password
            )
            print(f"✓ Password entry for '{service}' added successfully!")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def retrieve_password(self):
        """Retrieve a stored password."""
        print("\n--- Retrieve Password ---")
        
        service = input("Service name: ").strip()
        if not service:
            print("❌ Service name cannot be empty")
            return
        
        try:
            entry = self.storage.get_entry(service, self.master_password)
            
            if entry:
                print(f"\n{'Service:':<15} {entry['service']}")
                print(f"{'Username:':<15} {entry['username']}")
                print(f"{'Password:':<15} {entry['password']}")
                if entry.get('url'):
                    print(f"{'URL:':<15} {entry['url']}")
                if entry.get('notes'):
                    print(f"{'Notes:':<15} {entry['notes']}")
            else:
                print(f"❌ No entry found for '{service}'")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def update_password(self):
        """Update an existing password entry."""
        print("\n--- Update Password Entry ---")
        
        service = input("Service name: ").strip()
        if not service:
            print("❌ Service name cannot be empty")
            return
        
        # Check if exists
        entry = self.storage.get_entry(service, self.master_password)
        if not entry:
            print(f"❌ No entry found for '{service}'")
            return
        
        print("\nLeave blank to keep current value")
        print(f"Current username: {entry['username']}")
        new_username = input("New username (optional): ").strip()
        
        new_password = None
        if input("Change password? (y/n): ").lower() == 'y':
            new_password = getpass.getpass("New password: ")
        
        print(f"Current URL: {entry.get('url', '(none)')}")
        new_url = input("New URL (optional): ").strip() or None
        
        print(f"Current notes: {entry.get('notes', '(none)')}")
        new_notes = input("New notes (optional): ").strip() or None
        
        try:
            self.storage.update_entry(
                service=service,
                master_password=self.master_password,
                username=new_username or None,
                password=new_password,
                url=new_url,
                notes=new_notes
            )
            print(f"✓ Entry for '{service}' updated successfully!")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def delete_password(self):
        """Delete a password entry."""
        print("\n--- Delete Password Entry ---")
        
        service = input("Service name: ").strip()
        if not service:
            print("❌ Service name cannot be empty")
            return
        
        confirm = input(f"Are you sure you want to delete '{service}'? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Cancelled")
            return
        
        try:
            if self.storage.delete_entry(service, self.master_password):
                print(f"✓ Entry for '{service}' deleted successfully!")
            else:
                print(f"❌ No entry found for '{service}'")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def search_passwords(self):
        """Search password entries."""
        print("\n--- Search Passwords ---")
        
        query = input("Search query (service name or username): ").strip()
        if not query:
            print("❌ Search query cannot be empty")
            return
        
        try:
            results = self.storage.search_entries(query, self.master_password)
            
            if results:
                print(f"\nFound {len(results)} matching entries:\n")
                for i, entry in enumerate(results, 1):
                    print(f"{i}. Service: {entry['service']}")
                    print(f"   Username: {entry['username']}")
                    if entry.get('url'):
                        print(f"   URL: {entry['url']}")
                    print()
            else:
                print("❌ No matching entries found")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def list_all_passwords(self):
        """List all password entries (without passwords)."""
        print("\n--- All Entries ---")
        
        try:
            entries = self.storage.list_all_entries(self.master_password)
            
            if entries:
                print(f"\nTotal entries: {len(entries)}\n")
                for i, entry in enumerate(entries, 1):
                    print(f"{i}. Service: {entry['service']}")
                    print(f"   Username: {entry['username']}")
                    if entry['url']:
                        print(f"   URL: {entry['url']}")
                    print()
            else:
                print("No entries stored yet")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def logout(self):
        """Logout and clear master password from memory."""
        self.master_password = None
        self.authenticated = False
        print("✓ Logged out successfully")
    
    def run(self):
        """Main loop for the CLI."""
        print("\n" + "="*50)
        print("WELCOME TO PASSWORD MANAGER")
        print("="*50)
        
        # Check if this is first run
        if not self.storage.master_password_hash_file.exists():
            print("\nNo master password set. Setting up now...")
            self.setup_master_password()
        
        while True:
            self.print_menu()
            
            choice = input("Select an option (1-8): ").strip()
            
            if not self.authenticated:
                if choice == '1':
                    self.setup_master_password()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    print("\nThank you for using Password Manager. Goodbye!")
                    sys.exit(0)
                else:
                    print("❌ Invalid option")
            else:
                if choice == '1':
                    self.add_password()
                elif choice == '2':
                    self.retrieve_password()
                elif choice == '3':
                    self.update_password()
                elif choice == '4':
                    self.delete_password()
                elif choice == '5':
                    self.search_passwords()
                elif choice == '6':
                    self.list_all_passwords()
                elif choice == '7':
                    self.logout()
                elif choice == '8':
                    print("\nThank you for using Password Manager. Goodbye!")
                    sys.exit(0)
                else:
                    print("❌ Invalid option")


def main():
    """Entry point for the application."""
    try:
        manager = PasswordManagerCLI()
        manager.run()
    except KeyboardInterrupt:
        print("\n\nPassword Manager closed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
