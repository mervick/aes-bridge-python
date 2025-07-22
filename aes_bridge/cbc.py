# This file is part of AesBridge - modern cross-language AES encryption library
# Repository: https://github.com/mervick/aes-bridge
#
# Copyright Andrey Izman (c) 2018-2025 <izmanw@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from common import to_bytes, generate_random


def derive_keys(passphrase: bytes, salt: bytes) -> tuple:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,  # 32 for AES key, 32 for HMAC key
        salt=salt,
        iterations=100_000,
    )
    key_material = kdf.derive(passphrase)
    return key_material[:32], key_material[32:]  # AES key, HMAC key

def encrypt_cbc_bin(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Encrypts data using AES-CBC mode with HMAC authentication.

    @param data: Data to encrypt
    @param passphrase: Encryption passphrase

    @return: Encrypted data in format: salt (16 bytes) + IV (16 bytes) +
             ciphertext (variable length) + HMAC tag (32 bytes).
    """
    passphrase = to_bytes(passphrase)
    plaintext = to_bytes(data)
    salt = generate_random(16)
    iv = generate_random(16)
    aes_key, hmac_key = derive_keys(passphrase, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    mac = hmac.HMAC(hmac_key, hashes.SHA256())
    mac.update(iv + ciphertext)
    tag = mac.finalize()

    return salt + iv + ciphertext + tag

def decrypt_cbc_bin(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Decrypts data encrypted with encrypt_cbc_bin() function.

    @param data: Encrypted data in format from encrypt_cbc_bin():
                 salt (16) + IV (16) + ciphertext (N) + HMAC (32)
    @param passphrase: passphrase used for encryption
    """
    passphrase = to_bytes(passphrase)
    data = to_bytes(data)
    salt = data[:16]
    iv = data[16:32]
    tag = data[-32:]
    ciphertext = data[32:-32]

    aes_key, hmac_key = derive_keys(passphrase, salt)

    mac = hmac.HMAC(hmac_key, hashes.SHA256())
    mac.update(iv + ciphertext)
    mac.verify(tag)  # raises exception if tag invalid

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def encrypt_cbc(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Encrypts data and returns result as base64 encoded bytes.

    @param data: Data to encrypt
    @param passphrase: Encryption passphrase
    """
    return base64.b64encode(encrypt_cbc_bin(data, passphrase))

def decrypt_cbc(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Decrypts base64 encoded data encrypted with encrypt_cbc().

    @param data: Base64 encoded encrypted data
    @param passphrase: Encryption passphrase
    """
    return decrypt_cbc_bin(base64.b64decode(data), passphrase)
