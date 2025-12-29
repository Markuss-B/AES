import unittest
from AES_core import hex_to_bytes
from CBC_core import cbc_encrypt, cbc_decrypt

class TestCBC(unittest.TestCase):
    def test_cbc_roundtrip(self):
        key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
        iv  = hex_to_bytes("0f0e0d0c0b0a09080706050403020100")
        pt  = bytes.fromhex("00112233445566778899aabbccddeeff" "010203")  # not multiple of 16 -> padding
        ct  = cbc_encrypt(key, iv, pt)
        back = cbc_decrypt(key, iv, ct)
        self.assertEqual(back, pt)

if __name__ == "__main__":
    unittest.main()
