#!/usr/bin/env python3

import argparse
import base64
import sys
from aes_bridge import encrypt_cbc, decrypt_cbc
from aes_bridge import encrypt_gcm, decrypt_gcm
from aes_bridge import encrypt_legacy, decrypt_legacy

def main():
    parser = argparse.ArgumentParser(description="AES Encryption/Decryption CLI for AesBridge-Python.")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform: 'encrypt' or 'decrypt'.")
    parser.add_argument("--mode", choices=["cbc", "gcm", "legacy"], required=True, help="Encryption mode.")
    parser.add_argument("--data", required=True, help="Data to encrypt (UTF-8 string) or decrypt (base64 string).")
    parser.add_argument("--passphrase", required=True, help="Passphrase for key derivation.")
    parser.add_argument("--b64", help="Accept base64 encoded input and returns base64 encoded output.", action="store_true")

    args = parser.parse_args()

    try:
        data = args.data
        if args.action == "encrypt":
            if args.b64:
                data = base64.b64decode(data)

        if args.mode == "cbc":
            if args.action == "encrypt":
                print(encrypt_cbc(data, args.passphrase).decode('utf-8'))
            elif args.action == "decrypt":
                decrypted = decrypt_cbc(data, args.passphrase)
                if args.b64:
                    decrypted = base64.b64encode(decrypted).decode('utf-8')
                print(decrypted)

        elif args.mode == "gcm":
            if args.action == "encrypt":
                print(encrypt_gcm(data, args.passphrase).decode('utf-8'))
            elif args.action == "decrypt":
                decrypted = decrypt_gcm(data, args.passphrase)
                if args.b64:
                    decrypted = base64.b64encode(decrypted).decode('utf-8')
                print(decrypted)

        elif args.mode == "legacy":
            if args.action == "encrypt":
                print(encrypt_legacy(data, args.passphrase).decode('utf-8'))
            elif args.action == "decrypt":
                decrypted = decrypt_legacy(data, args.passphrase)
                if args.b64:
                    decrypted = base64.b64encode(decrypted).decode('utf-8')
                print(decrypted)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
