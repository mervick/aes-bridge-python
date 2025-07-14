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

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from cbc import encrypt_cbc, decrypt_cbc, encrypt_cbc_bin, decrypt_cbc_bin
from gcm import encrypt_gcm, decrypt_gcm, encrypt_gcm_bin, decrypt_gcm_bin
from legacy import encrypt_legacy, decrypt_legacy

encrypt = encrypt_gcm
decrypt = decrypt_gcm

__all__       = ['encrypt',         'decrypt', 
                 'encrypt_cbc',     'decrypt_cbc', 
                 'encrypt_cbc_bin', 'decrypt_cbc_bin',
                 'encrypt_gcm',     'decrypt_gcm', 
                 'encrypt_gcm_bin', 'decrypt_gcm_bin',
                 'encrypt_legacy',  'decrypt_legacy']
__revision__  = "$Id$"
__author__    = "Andrey Izman"
__email__     = "izmanw@gmail.com"
__copyright__ = "Copyright 2018-2025 Andrey Izman"
__license__   = "MIT"

