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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from common import to_bytes, generate_random


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    ).derive(passphrase)

def encrypt_gcm_bin(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Encrypt data with AES-GCM.

    @param data: Data to encrypt
    @param passphrase: Encryption passphrase

    @return: Encrypted data in format:
             salt(16) + nonce(12) + ciphertext + tag(16)
    """
    passphrase = to_bytes(passphrase)
    plaintext = to_bytes(data)
    # salt = urandom(16)
    salt = generate_random(16)
    # nonce = urandom(12)
    nonce = generate_random(12)
    key = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return salt + nonce + ciphertext + encryptor.tag  # type: ignore

def decrypt_gcm_bin(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Decrypt data encrypted by encrypt_gcm_bin().

    @param data: Encrypted data
    @param passphrase: Encryption passphrase
    """
    data = to_bytes(data)
    passphrase = to_bytes(passphrase)

    salt = data[:16]
    nonce = data[16:28]
    tag = data[-16:]
    ciphertext = data[28:-16]

    key = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_gcm(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Encrypt data using AES-GCM and encode result to base64.

    @param data: Data to encrypt
    @param passphrase: Encryption passphrase
    """
    return base64.b64encode(encrypt_gcm_bin(data, passphrase))

def decrypt_gcm(data: bytes | str, passphrase: bytes | str) -> bytes:
    """
    Decrypt base64 encoded data encrypted by encrypt_gcm().

    @param data: Base64 encoded encrypted data
    @param passphrase: Encryption passphrase
    """
    return decrypt_gcm_bin(base64.b64decode(to_bytes(data)), passphrase)
