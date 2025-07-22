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
from hashlib import md5
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from common import to_bytes, generate_random

BLOCK_SIZE = 16
KEY_LEN = 32
IV_LEN = 16


def encrypt_legacy(data: str | bytes, passphrase: str | bytes) -> bytes:
    """
    Encrypts plaintext using AES-256-CBC with OpenSSL-compatible output (Salted__ + salt + ciphertext),
    then base64-encodes the result.

    @param data: Plaintext data to encrypt (string or bytes)
    @param passphrase: Passphrase for key derivation
    @return: Encrypted data, base64-encoded as bytes
    """
    salt = generate_random(8)
    key, iv = __derive_key_and_iv(passphrase, salt)
    padded = __pkcs7_padding(data)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ciphertext = cipher.update(padded) + cipher.finalize()
    return base64.b64encode(b'Salted__' + salt + ciphertext)

def decrypt_legacy(data: str | bytes, passphrase: str | bytes) -> bytes:
    """
    Decrypts base64-encoded AES-CBC data with OpenSSL-compatible format (Salted__ + salt + ciphertext).

    @param data: Encrypted data, base64-encoded string or bytes
    @param passphrase: Passphrase for key derivation
    @type data: str | bytes
    @type passphrase: str | bytes
    @return: Decrypted plaintext as raw bytes
    @rtype: bytes
    """
    ct = base64.b64decode(data)
    if ct[:8] != b'Salted__':
        return b''
    salt = ct[8:16]
    key, iv = __derive_key_and_iv(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    decrypted = cipher.update(ct[16:]) + cipher.finalize()
    return __pkcs7_trimming(decrypted)

def __pkcs7_padding(s: str | bytes) -> bytes:
    s = to_bytes(s)
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    return s + bytes([pad_len] * pad_len)

def __pkcs7_trimming(s) -> bytes:
    return s[:-s[-1]]

def __derive_key_and_iv(password: str | bytes, salt: bytes) -> tuple:
    d = d_i = b''
    password = to_bytes(password)
    while len(d) < KEY_LEN + IV_LEN:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:KEY_LEN], d[KEY_LEN:KEY_LEN + IV_LEN]
