from __future__ import annotations

from typing import List, Tuple
from AES_tables import SBOX, RCON, INV_SBOX


BLOCK_SIZE = 16  # bytes


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert a hex string (e.g. '001122...') into bytes.
    Accepts upper/lowercase; strips spaces/newlines.
    """
    s = "".join(hex_str.strip().split()).lower()
    if len(s) != 2 * BLOCK_SIZE:
        raise ValueError(f"Expected {2*BLOCK_SIZE} hex chars, got {len(s)}")
    if any(ch not in "0123456789abcdef" for ch in s):
        raise ValueError("Hex string contains invalid characters")
    return bytes.fromhex(s)

def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to lowercase hex without spaces."""
    return b.hex()

# State is a 4x4 matrix of bytes: state[row][col]
State = List[List[int]]  # each int in 0..255


def bytes_to_state(block: bytes) -> State:
    """
    Map 16 input bytes into AES state (4x4) using FIPS-197 layout:
    state[r][c] = block[r + 4*c]
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Block must be exactly 16 bytes")

    state: State = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = block[r + 4 * c]
    return state


def state_to_bytes(state: State) -> bytes:
    """
    Inverse mapping of bytes_to_state:
    block[r + 4*c] = state[r][c]
    """
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("State must be 4x4")

    out = bytearray(BLOCK_SIZE)
    for c in range(4):
        for r in range(4):
            val = state[r][c]
            if not (0 <= val <= 255):
                raise ValueError("State entries must be bytes (0..255)")
            out[r + 4 * c] = val
    return bytes(out)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("xor_bytes inputs must have same length")
    return bytes(x ^ y for x, y in zip(a, b))

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


Word = Tuple[int, int, int, int]  # 4 bytes

def _rot_word(w: Word) -> Word:
    # [b0,b1,b2,b3] -> [b1,b2,b3,b0]
    return (w[1], w[2], w[3], w[0])

def _sub_word(w: Word) -> Word:
    return (SBOX[w[0]], SBOX[w[1]], SBOX[w[2]], SBOX[w[3]])

def _xor_words(a: Word, b: Word) -> Word:
    return (a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3])

def _word_from_bytes(b: bytes, i: int) -> Word:
    # word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
    off = 4 * i
    return (b[off], b[off + 1], b[off + 2], b[off + 3])

def _words_to_bytes(words: List[Word]) -> bytes:
    out = bytearray()
    for w in words:
        out.extend(w)
    return bytes(out)

def key_expansion_128(key: bytes) -> List[bytes]:
    """
    AES-128 KeyExpansion.
    Returns 11 round keys (round 0..10), each 16 bytes.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    Nk, Nb, Nr = 4, 4, 10
    w: List[Word] = [None] * (Nb * (Nr + 1))  # 44 words

    # w[0..3] from the cipher key
    for i in range(Nk):
        w[i] = _word_from_bytes(key, i)

    # expand
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp))
            # temp XOR Rcon[i/Nk] where Rcon is a word [rc,0,0,0]
            rc = RCON[i // Nk]
            temp = (temp[0] ^ rc, temp[1], temp[2], temp[3])
        w[i] = _xor_words(w[i - Nk], temp)

    # group into round keys (each 4 words => 16 bytes)
    round_keys: List[bytes] = []
    for r in range(Nr + 1):
        rk_words = w[r * Nb : (r + 1) * Nb]
        round_keys.append(_words_to_bytes(rk_words))
    return round_keys

# round op helpers
def round_keys_as_states(key: bytes) -> List[State]:
    """Return 11 round keys (round 0..10) as 4x4 state matrices."""
    rks_bytes = key_expansion_128(key)
    return [bytes_to_state(rk) for rk in rks_bytes]

def xtime(x: int) -> int:
    """Multiply by {02} in GF(2^8)."""
    x &= 0xFF
    res = (x << 1) & 0xFF
    if x & 0x80:
        res ^= 0x1B
    return res

# round ops
def add_round_key(state: State, round_key: State) -> None:
    """state[r][c] ^= round_key[r][c]"""
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]

def sub_bytes(state: State) -> None:
    """Apply Rijndael S-box to every byte in the state."""
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def shift_rows(state: State) -> None:
    """
    Row 0: no shift
    Row 1: left shift 1
    Row 2: left shift 2
    Row 3: left shift 3
    """
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def mix_columns(state: State) -> None:
    """
    MixColumns on each column using:
    b0 = 2*a0 + 3*a1 + a2 + a3
    b1 = a0 + 2*a1 + 3*a2 + a3
    b2 = a0 + a1 + 2*a2 + 3*a3
    b3 = 3*a0 + a1 + a2 + 2*a3
    where + is XOR in GF(2^8), and 2*x = xtime(x), 3*x = xtime(x) ^ x.
    """
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        m2_0, m2_1, m2_2, m2_3 = xtime(a0), xtime(a1), xtime(a2), xtime(a3)
        m3_0, m3_1, m3_2, m3_3 = m2_0 ^ a0, m2_1 ^ a1, m2_2 ^ a2, m2_3 ^ a3

        state[0][c] = (m2_0 ^ m3_1 ^ a2 ^ a3) & 0xFF
        state[1][c] = (a0 ^ m2_1 ^ m3_2 ^ a3) & 0xFF
        state[2][c] = (a0 ^ a1 ^ m2_2 ^ m3_3) & 0xFF
        state[3][c] = (m3_0 ^ a1 ^ a2 ^ m2_3) & 0xFF

def state_to_hex(state: State) -> str:
    return state_to_bytes(state).hex()

def clone_state(state: State) -> State:
    return [row[:] for row in state]

def aes_encrypt_block(key: bytes, block: bytes, trace: bool = False) -> bytes:
    """
    AES-128 encrypt one 16-byte block.

    If trace=True, prints round[ r].start / s_box / s_row / m_col / k_sch
    in the same style as FIPS Appendix C.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")

    rk_states = round_keys_as_states(key)  # 11 round keys as 4x4 states (round 0..10)
    state = bytes_to_state(block)

    if trace:
        print(f"round[ 0].input  {state_to_hex(state)}")
        print(f"round[ 0].k_sch  {state_to_hex(rk_states[0])}")

    # round 0
    add_round_key(state, rk_states[0])

    # rounds 1..9
    for r in range(1, 10):
        if trace:
            print(f"round[{r:2d}].start  {state_to_hex(state)}")

        sub_bytes(state)
        if trace:
            print(f"round[{r:2d}].s_box  {state_to_hex(state)}")

        shift_rows(state)
        if trace:
            print(f"round[{r:2d}].s_row  {state_to_hex(state)}")

        mix_columns(state)
        if trace:
            print(f"round[{r:2d}].m_col  {state_to_hex(state)}")
            print(f"round[{r:2d}].k_sch  {state_to_hex(rk_states[r])}")

        add_round_key(state, rk_states[r])

    # final round (r = 10): no MixColumns
    if trace:
        print(f"round[10].start  {state_to_hex(state)}")

    sub_bytes(state)
    if trace:
        print(f"round[10].s_box  {state_to_hex(state)}")

    shift_rows(state)
    if trace:
        print(f"round[10].s_row  {state_to_hex(state)}")
        print(f"round[10].k_sch  {state_to_hex(rk_states[10])}")

    add_round_key(state, rk_states[10])

    if trace:
        print(f"round[10].output {state_to_hex(state)}")

    return state_to_bytes(state)

# inv ops
def inv_sub_bytes(state: State) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def inv_shift_rows(state: State) -> None:
    # Row 0 unchanged; rows 1..3 shift RIGHT by row index.
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def _inv_mul_tables(x: int) -> tuple[int, int, int, int]:
    """
    Compute x * {09}, x * {0b}, x * {0d}, x * {0e} in GF(2^8),
    using ONLY 3 xtime() applications

    Let:
      x2 = x*{02}, x4 = x*{04}, x8 = x*{08}
    Then:
      x*{09} = x8 ^ x
      x*{0b} = x8 ^ x2 ^ x
      x*{0d} = x8 ^ x4 ^ x
      x*{0e} = x8 ^ x4 ^ x2
    """
    x &= 0xFF
    x2 = xtime(x)
    x4 = xtime(x2)
    x8 = xtime(x4)

    mul09 = x8 ^ x
    mul0b = x8 ^ x2 ^ x
    mul0d = x8 ^ x4 ^ x
    mul0e = x8 ^ x4 ^ x2
    return mul09 & 0xFF, mul0b & 0xFF, mul0d & 0xFF, mul0e & 0xFF

def inv_mix_columns(state: State) -> None:
    """
    Inverse MixColumns (Decryption), per the lecture formulas:

      a0 = {0e}*b0 ^ {0b}*b1 ^ {0d}*b2 ^ {09}*b3
      a1 = {09}*b0 ^ {0e}*b1 ^ {0b}*b2 ^ {0d}*b3
      a2 = {0d}*b0 ^ {09}*b1 ^ {0e}*b2 ^ {0b}*b3
      a3 = {0b}*b0 ^ {0d}*b1 ^ {09}*b2 ^ {0e}*b3
    """
    for c in range(4):
        b0, b1, b2, b3 = state[0][c], state[1][c], state[2][c], state[3][c]

        b0_09, b0_0b, b0_0d, b0_0e = _inv_mul_tables(b0)
        b1_09, b1_0b, b1_0d, b1_0e = _inv_mul_tables(b1)
        b2_09, b2_0b, b2_0d, b2_0e = _inv_mul_tables(b2)
        b3_09, b3_0b, b3_0d, b3_0e = _inv_mul_tables(b3)

        state[0][c] = (b0_0e ^ b1_0b ^ b2_0d ^ b3_09) & 0xFF
        state[1][c] = (b0_09 ^ b1_0e ^ b2_0b ^ b3_0d) & 0xFF
        state[2][c] = (b0_0d ^ b1_09 ^ b2_0e ^ b3_0b) & 0xFF
        state[3][c] = (b0_0b ^ b1_0d ^ b2_09 ^ b3_0e) & 0xFF

def aes_decrypt_block(key: bytes, block: bytes, trace: bool = False) -> bytes:
    """
    AES-128 InvCipher for one 16-byte block. 
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")

    rk_states = round_keys_as_states(key)  # round 0..10
    state = bytes_to_state(block)

    if trace:
        print(f"round[ 0].iinput  {state_to_bytes(state).hex()}")
        print(f"round[ 0].ik_sch  {state_to_bytes(rk_states[10]).hex()}")

    # initial AddRoundKey with last round key
    add_round_key(state, rk_states[10])

    # rounds 9..1
    for r in range(9, 0, -1):
        if trace:
            print(f"round[{10-r:2d}].istart  {state_to_bytes(state).hex()}")

        inv_shift_rows(state)
        if trace:
            print(f"round[{10-r:2d}].is_row  {state_to_bytes(state).hex()}")

        inv_sub_bytes(state)
        if trace:
            print(f"round[{10-r:2d}].is_box  {state_to_bytes(state).hex()}")
            print(f"round[{10-r:2d}].ik_sch  {state_to_bytes(rk_states[r]).hex()}")

        add_round_key(state, rk_states[r])
        if trace:
            print(f"round[{10-r:2d}].ik_add  {state_to_bytes(state).hex()}")

        inv_mix_columns(state)

    # final round
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, rk_states[0])

    if trace:
        print(f"round[10].ioutput {state_to_bytes(state).hex()}")

    return state_to_bytes(state)

# demo
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

def _print_round_keys(round_keys: List[bytes]) -> None:
    for r, rk in enumerate(round_keys):
        print(f"Round {r:2d} key: {rk.hex()}")

def _demo_keyexpansion_fips_a1() -> None:
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
    _print_round_keys(rks)

def _demo_roundtrip(hex_block: str) -> None:
    block = hex_to_bytes(hex_block)
    st = bytes_to_state(block)

    print("Input block hex:", hex_block.lower())
    print_state(st, title="State (FIPS 4x4 layout):")

    block2 = state_to_bytes(st)
    assert block2 == block, "Roundtrip bytes->state->bytes failed!"
    print("Roundtrip hex:", bytes_to_hex(block2))


if __name__ == "__main__":
    # must be 32 hex chars = 16 bytes
    _demo_roundtrip("2b7e151628aed2a6abf7158809cf4f3c")
    _demo_keyexpansion_fips_a1()
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
