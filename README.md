# AesBridge Python

This module provides a modern cross-language interface for AES encryption and decryption (CBC, GCM).

## Quick Start

Install 

```
pip install aes-bridge
```

Usage
```python
from aes_bridge import encrypt, decrypt

ciphertext = encrypt("Text", "Password")
plaintext = decrypt(ciphertext, "Password")
```

## API

### Main Functions

- `encrypt(data, passphrase)`  
  Encrypts a string using AES-GCM (default).  
  **Returns:** base64-encoded string.
  
- `decrypt(ciphertext, passphrase)`  
  Decrypts a base64-encoded string encrypted with AES-GCM.

### CBC Mode

- `encrypt_cbc(data, passphrase)`  
  Encrypts a string using AES-CBC.  
  HMAC is used for integrity verification.
  **Returns:** base64-encoded string.  

- `decrypt_cbc(ciphertext, passphrase)`  
  Decrypts a base64-encoded string encrypted with AES-CBC and verifies HMAC.

- `encrypt_cbc_bin(data, passphrase)`  
  Returns encrypted binary data using AES-CBC with HMAC.

- `decrypt_cbc_bin(ciphertext, passphrase)`  
  Decrypts binary data encrypted with AES-CBC and verifies HMAC.

### GCM Mode

- `encrypt_gcm(data, passphrase)`  
  Encrypts a string using AES-GCM.
  **Returns:** base64-encoded string.

- `decrypt_gcm(ciphertext, passphrase)`  
  Decrypts a base64-encoded string encrypted with AES-GCM.

- `encrypt_gcm_bin(data, passphrase)`  
  Returns encrypted binary data using AES-GCM.

- `decrypt_gcm_bin(ciphertext, passphrase)`  
  Decrypts binary data encrypted with AES-GCM.

### Legacy Mode

- `encrypt_legacy(data, passphrase)`  
  Encrypts a string in the legacy AES Everywhere format.  
  **Warning:** Using `encrypt_legacy` is strongly discouraged.

- `decrypt_legacy(ciphertext, passphrase)`  
  Decrypts a string encrypted in the legacy AES Everywhere format.

