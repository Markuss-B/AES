from AES_core import hex_to_bytes, round_keys_as_states, bytes_to_state, add_round_key, sub_bytes, shift_rows, mix_columns, key_expansion_128, state_to_bytes, aes_decrypt_block, aes_encrypt_block, State, List

def print_state(state: State, title: str | None = None) -> None:
    """
    Print the AES state as a 4x4 table in the usual FIPS style.
    Each entry is shown as two hex digits.
    """
    if title:
        print(title)
    for r in range(4):
        row_hex = " ".join(f"{state[r][c]:02x}" for c in range(4))
        print(row_hex)

def demo_round_ops(key_hex: str, block_hex: str) -> None:
    key = hex_to_bytes(key_hex)
    block = hex_to_bytes(block_hex)

    rk_states = round_keys_as_states(key)  # 11 keys as 4x4

    state = bytes_to_state(block)
    print_state(state, "Start state:")

    add_round_key(state, rk_states[0])
    print_state(state, "After AddRoundKey (round 0):")

    sub_bytes(state)
    print_state(state, "After SubBytes:")

    shift_rows(state)
    print_state(state, "After ShiftRows:")

    mix_columns(state)
    print_state(state, "After MixColumns:")

def print_round_keys(round_keys: List[bytes]) -> None:
    for r, rk in enumerate(round_keys):
        print(f"Round {r:2d} key: {rk.hex()}")

def demo_keyexpansion_fips_a1() -> None:
    """
    Validates against FIPS-197 Appendix A.1
    """
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    key = bytes.fromhex(key_hex)
    rks = key_expansion_128(key)

    # Expected w0..w43 from FIPS-197 Appendix A.1 
    expected_words_hex = [
        "2b7e1516","28aed2a6","abf71588","09cf4f3c",
        "a0fafe17","88542cb1","23a33939","2a6c7605",
        "f2c295f2","7a96b943","5935807a","7359f67f",
        "3d80477d","4716fe3e","1e237e44","6d7a883b",
        "ef44a541","a8525b7f","b671253b","db0bad00",
        "d4d1c6f8","7c839d87","caf2b8bc","11f915bc",
        "6d88a37a","110b3efd","dbf98641","ca0093fd",
        "4e54f70e","5f5fc9f3","84a64fb2","4ea6dc4f",
        "ead27321","b58dbad2","312bf560","7f8d292f",
        "ac7766f3","19fadc21","28d12941","575c006e",
        "d014f9a8","c9ee2589","e13f0cc8","b6630ca6",
    ]

    # Rebuild words from our round keys to compare easily
    got_words_hex: List[str] = []
    for rk in rks:
        for i in range(0, 16, 4):
            got_words_hex.append(rk[i:i+4].hex())

    assert got_words_hex == expected_words_hex, "KeyExpansion mismatch vs FIPS Appendix A.1"
    print("OK: KeyExpansion matches FIPS-197 Appendix A.1")
    print_round_keys(rks)

def demo_roundtrip(hex_block: str) -> None:
    block = hex_to_bytes(hex_block)
    st = bytes_to_state(block)

    print("Input block hex:", hex_block.lower())
    print_state(st, title="State (FIPS 4x4 layout):")

    block2 = state_to_bytes(st)
    assert block2 == block, "Roundtrip bytes->state->bytes failed!"
    print("Roundtrip hex:", block2.hex())


if __name__ == "__main__":
    # must be 32 hex chars = 16 bytes
    demo_roundtrip("2b7e151628aed2a6abf7158809cf4f3c")
    demo_keyexpansion_fips_a1()
    demo_round_ops(
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3243f6a8885a308d313198a2e0370734",
    )
    key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    pt  = hex_to_bytes("00112233445566778899aabbccddeeff")
    ct = aes_encrypt_block(key, pt, trace=True)
    print("CIPHERTEXT:\t", ct.hex())
    dec_pt = aes_decrypt_block(key, ct, trace=True)
    print("DECRYPT:\t", dec_pt.hex())
    print("PLAINTEXT:\t", pt.hex())
    print("CIPHERTEXT:\t", ct.hex())
