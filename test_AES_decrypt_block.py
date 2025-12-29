import unittest
from AES_core import hex_to_bytes, aes_encrypt_block, aes_decrypt_block, bytes_to_state, state_to_bytes, round_keys_as_states, add_round_key

class TestAESDecryptBlock(unittest.TestCase):
    # FIPS-197 Appendix C.1 AES-128 
    KEY = "000102030405060708090a0b0c0d0e0f"
    PT  = "00112233445566778899aabbccddeeff"
    CT  = "69c4e0d86a7b0430d8cdb78070b4c55a"

    def test_decrypt_fips_c1(self):
        key = hex_to_bytes(self.KEY)
        ct  = hex_to_bytes(self.CT)
        pt  = aes_decrypt_block(key, ct, trace=False)
        self.assertEqual(pt.hex(), self.PT)

    def test_encrypt_then_decrypt_roundtrip(self):
        key = hex_to_bytes(self.KEY)
        pt  = hex_to_bytes(self.PT)
        ct  = aes_encrypt_block(key, pt, trace=False)
        back = aes_decrypt_block(key, ct, trace=False)
        self.assertEqual(back, pt)

    def test_initial_addroundkey_matches_fips_inverse_start(self):
        # Inverse Cipher: round[0].iinput then AddRoundKey with last key -> round[1].istart 
        key = hex_to_bytes(self.KEY)
        ct  = hex_to_bytes(self.CT)

        rk = round_keys_as_states(key)
        state = bytes_to_state(ct)
        add_round_key(state, rk[10])  # last round key

        # round[1].istart from FIPS inverse cipher listing
        expected_istart = "7ad5fda789ef4e272bca100b3d9ff59f"
        self.assertEqual(state_to_bytes(state).hex(), expected_istart)

if __name__ == "__main__":
    unittest.main()
