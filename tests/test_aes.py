import unittest
import json

from aes_bridge import encrypt_cbc, decrypt_cbc, encrypt_gcm, decrypt_gcm, encrypt_legacy, decrypt_legacy

class TestAesBridge(unittest.TestCase):
    pass

def add_test(name, method):
    # print(f"Adding test: {name}")
    setattr(TestAesBridge, name, method)

def load_dynamic_tests():
    with open('tests/test_data.json', 'r') as f:
        test_data = json.load(f)

    def test_encrypt_cbc_not_empty(value):
        def test(self):
            encrypted = encrypt_cbc(value, value)
            self.assertTrue(encrypted, "Encryption result should not be empty")
        return test

    def test_encrypt_gcm_not_empty(value):
        def test(self):
            encrypted = encrypt_gcm(value, value)
            self.assertTrue(encrypted, "Encryption result should not be empty")
        return test

    def test_encrypt_legacy_not_empty(value):
        def test(self):
            encrypted = encrypt_legacy(value, value)
            self.assertTrue(encrypted, "Encryption result should not be empty")
        return test

    def test_encrypt_decrypt_cbc(value):
        def test(self):
            encrypted = encrypt_cbc(value, value)
            decrypted = decrypt_cbc(encrypted, value)
            self.assertEqual(value, decrypted, "CBC encryption/decryption failed")
        return test

    def test_encrypt_decrypt_gcm(value):
        def test(self):
            encrypted = encrypt_gcm(value, value)
            decrypted = decrypt_gcm(encrypted, value)
            self.assertEqual(value, decrypted, "GCM encryption/decryption failed")
        return test

    def test_encrypt_decrypt_legacy(value):
        def test(self):
            encrypted = encrypt_legacy(value, value)
            decrypted = decrypt_legacy(encrypted, value)
            self.assertEqual(value, decrypted, "CBC encryption/decryption failed")
        return test

    def test_decrypt_cbc(encrypted, passphrase, result):
        def test(self):
            decrypted = decrypt_cbc(encrypted, passphrase)
            self.assertEqual(result, decrypted, "CBC decryption failed")
        return test

    def test_decrypt_gcm(encrypted, passphrase, result):
        def test(self):
            decrypted = decrypt_gcm(encrypted, passphrase)
            self.assertEqual(result, decrypted, "GCM decryption failed")
        return test

    def test_decrypt_legacy(encrypted, passphrase, result):
        def test(self):
            decrypted = decrypt_legacy(encrypted, passphrase)
            self.assertEqual(result, decrypted, "Legacy decryption failed")
        return test

    test_key = 'plaintext'
    for idx, test_case in enumerate(test_data.get('testdata', {}).get('plaintext', [])):
        test_case = test_case.encode('utf-8')
        add_test(f'test_0_{test_key}_encrypt_cbc_not_empty_{idx}', test_encrypt_cbc_not_empty(test_case))
        add_test(f'test_0_{test_key}_encrypt_gcm_not_empty_{idx}', test_encrypt_gcm_not_empty(test_case))
        add_test(f'test_0_{test_key}_encrypt_legacy_not_empty_{idx}', test_encrypt_legacy_not_empty(test_case))

        add_test(f'test_1_{test_key}_encrypt_decrypt_cbc_{idx}', test_encrypt_decrypt_cbc(test_case))
        add_test(f'test_1_{test_key}_encrypt_decrypt_gcm_{idx}', test_encrypt_decrypt_gcm(test_case))
        add_test(f'test_1_{test_key}_encrypt_decrypt_legacy_{idx}', test_encrypt_decrypt_legacy(test_case))

    test_key = 'hex'
    for idx, test_case in enumerate(test_data.get('testdata', {}).get('hex', [])):
        test_text = bytes.fromhex(test_case)
        add_test(f'test_2_{test_key}_encrypt_cbc_not_empty_{idx}', test_encrypt_cbc_not_empty(test_text))
        add_test(f'test_2_{test_key}_encrypt_gcm_not_empty_{idx}', test_encrypt_gcm_not_empty(test_text))
        add_test(f'test_2_{test_key}_encrypt_legacy_not_empty_{idx}', test_encrypt_legacy_not_empty(test_text))

        add_test(f'test_3_{test_key}_encrypt_decrypt_cbc_{idx}', test_encrypt_decrypt_cbc(test_text))
        add_test(f'test_3_{test_key}_encrypt_decrypt_gcm_{idx}', test_encrypt_decrypt_gcm(test_text))
        add_test(f'test_3_{test_key}_encrypt_decrypt_legacy_{idx}', test_encrypt_decrypt_legacy(test_text))

    for idx, test_case in enumerate(test_data.get('decrypt', [])):
        test_key = test_case.get('id', f'case_{idx}')
        plaintext = test_case.get('plaintext')
        hex_data = test_case.get('hex')
        passphrase = test_case.get('passphrase')
        encrypted_cbc = test_case.get('encrypted-cbc')
        encrypted_gcm = test_case.get('encrypted-gcm')
        encrypted_legacy = test_case.get('encrypted-legacy')

        if passphrase is None or (plaintext is None and hex_data is None) or \
           (encrypted_cbc is None and encrypted_gcm is None and encrypted_legacy is None):
            continue

        if plaintext is not None:
            plaintext = plaintext.encode('utf-8')
        elif hex_data is not None:
            plaintext = bytes.fromhex(hex_data)

        if encrypted_cbc is not None:
            add_test(f'test_9_decrypt_cbc_{test_key}', test_decrypt_cbc(encrypted_cbc, passphrase, plaintext))
        if encrypted_gcm is not None:
            add_test(f'test_9_decrypt_gcm_{test_key}', test_decrypt_gcm(encrypted_gcm, passphrase, plaintext))
        if encrypted_legacy is not None:
            add_test(f'test_9_decrypt_legacy_{test_key}', test_decrypt_legacy(encrypted_legacy, passphrase, plaintext))


load_dynamic_tests()

if __name__ == '__main__':
    unittest.main()
