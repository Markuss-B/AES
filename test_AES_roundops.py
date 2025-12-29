import unittest

from AES_core import (
    hex_to_bytes,
    bytes_to_state,
    state_to_bytes,
    round_keys_as_states,
    add_round_key,
    sub_bytes,
    shift_rows,
    mix_columns,
)


class TestAESRoundOps(unittest.TestCase):
    # FIPS-197 Appendix C.1 AES-128 vectors
    KEY_HEX = "000102030405060708090a0b0c0d0e0f"
    PT_HEX  = "00112233445566778899aabbccddeeff"

    # Intermediate values for round 1
    ROUND1_START = "00102030405060708090a0b0c0d0e0f0"
    ROUND1_SBOX  = "63cab7040953d051cd60e0e7ba70e18c"
    ROUND1_SROW  = "6353e08c0960e104cd70b751bacad0e7"
    ROUND1_MCOL  = "5f72641557f5bc92f7be3b291db9f91a"

    def test_roundkey0_equals_key(self):
        key = hex_to_bytes(self.KEY_HEX)
        rk_states = round_keys_as_states(key)
        rk0_bytes = state_to_bytes(rk_states[0])
        self.assertEqual(rk0_bytes.hex(), self.KEY_HEX)

    def test_round1_step_by_step(self):
        key = hex_to_bytes(self.KEY_HEX)
        pt  = hex_to_bytes(self.PT_HEX)

        rk_states = round_keys_as_states(key)
        state = bytes_to_state(pt)

        # AddRoundKey with round 0 key -> round[1].start
        add_round_key(state, rk_states[0])
        self.assertEqual(state_to_bytes(state).hex(), self.ROUND1_START)

        # SubBytes -> round[1].s_box
        sub_bytes(state)
        self.assertEqual(state_to_bytes(state).hex(), self.ROUND1_SBOX)

        # ShiftRows -> round[1].s_row
        shift_rows(state)
        self.assertEqual(state_to_bytes(state).hex(), self.ROUND1_SROW)

        # MixColumns -> round[1].m_col
        mix_columns(state)
        self.assertEqual(state_to_bytes(state).hex(), self.ROUND1_MCOL)

    def test_add_round_key_is_its_own_inverse(self):
        key = hex_to_bytes(self.KEY_HEX)
        pt  = hex_to_bytes(self.PT_HEX)

        rk_states = round_keys_as_states(key)
        s = bytes_to_state(pt)
        original = state_to_bytes(s)

        add_round_key(s, rk_states[0])
        add_round_key(s, rk_states[0])
        self.assertEqual(state_to_bytes(s), original)


if __name__ == "__main__":
    unittest.main()
