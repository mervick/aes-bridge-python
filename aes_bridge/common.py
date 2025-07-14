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

from os import urandom
import hashlib


_nonce = int.from_bytes(urandom(8), 'big')

def generate_random(size: int) -> bytes:
    """ Generates random bytes of specified size. """
    global _nonce
    _nonce += 1
    nonce_bytes = _nonce.to_bytes(8, 'big')
    data = urandom(13) + nonce_bytes + urandom(13)
    return hashlib.sha256(data).digest()[:size]


def to_bytes(s: str | bytes) -> bytes:
    """ Convert string to bytes. """
    return s.encode('utf-8') if isinstance(s, str) else s
