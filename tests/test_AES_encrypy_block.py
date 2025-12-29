import unittest

from AES_core import hex_to_bytes, aes_encrypt_block

class TestAESEncryptBlock(unittest.TestCase):
    # FIPS-197 Appendix C.1 AES-128 example
    def test_fips_c1_vector(self):
        key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
        pt  = hex_to_bytes("00112233445566778899aabbccddeeff")
        expected_ct = "69c4e0d86a7b0430d8cdb78070b4c55a"
        ct = aes_encrypt_block(key, pt, trace=False)
        self.assertEqual(ct.hex(), expected_ct)

    # FIPS-197 Appendix B cipher example final output is 39 25 84 1d ... in the diagram 
    def test_fips_appendix_b_output(self):
        key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
        pt  = hex_to_bytes("3243f6a8885a308d313198a2e0370734")
        expected_ct = "3925841d02dc09fbdc118597196a0b32" # shown as output in Appendix B 
        ct = aes_encrypt_block(key, pt, trace=False)
        self.assertEqual(ct.hex(), expected_ct)

if __name__ == "__main__":
    unittest.main()
