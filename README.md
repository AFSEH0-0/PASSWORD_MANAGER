# PASSWORD_MANAGER
On first execution:

========================================
         PYTHON PASSWORD MANAGER
========================================

=== First-Time Setup ===
Create your master password.
This password protects the entire vault.

Create master password:
Confirm master password:

Vault created successfully.
Encrypted vault: /home/user/.password-vault.enc

Then you get the numeric interface:

========================================
          PASSWORD MANAGER
========================================
1. Add password
2. View password
3. List passwords
4. Search passwords
5. Delete password
6. Generate password
7. Change master password
8. Vault information
9. Exit
========================================
Select option:

For example, selecting 1:

========== ADD PASSWORD ==========
Website/service: github.com
Username/email: user@example.com

Password options:
1. Enter password manually
2. Generate secure password

Choose option: 2

Generated password:
xK7!qP2@vL9#sR4$mT8&

Save this password? [Y/n]: y
Notes (optional): Main GitHub account

Password saved successfully.
Storage

The actual vault is:

~/.password-vault.enc

It contains encrypted data rather than readable credentials. Conceptually, the file looks like:

{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": 600000,
  "salt": "...",
  "nonce": "...",
  "ciphertext": "..."
}
