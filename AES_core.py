from typing import List, Tuple
from AES_tables import SBOX, RCON, INV_SBOX

BLOCK_SIZE = 16  # bytes

# State is a 4x4 matrix of bytes: state[row][col]
State = List[List[int]]  # each int in 0..255
Word = Tuple[int, int, int, int]  # 4 bytes

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

def rot_word(w: Word) -> Word:
    # [b0,b1,b2,b3] -> [b1,b2,b3,b0]
    return (w[1], w[2], w[3], w[0])

def sub_word(w: Word) -> Word:
    return (SBOX[w[0]], SBOX[w[1]], SBOX[w[2]], SBOX[w[3]])

def xor_words(a: Word, b: Word) -> Word:
    return (a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3])

def word_from_bytes(b: bytes, i: int) -> Word:
    # word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
    off = 4 * i
    return (b[off], b[off + 1], b[off + 2], b[off + 3])

def words_to_bytes(words: List[Word]) -> bytes:
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
        w[i] = word_from_bytes(key, i)

    # expand
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            # temp XOR Rcon[i/Nk] where Rcon is a word [rc,0,0,0]
            rc = RCON[i // Nk]
            temp = (temp[0] ^ rc, temp[1], temp[2], temp[3])
        w[i] = xor_words(w[i - Nk], temp)

    # group into round keys (each 4 words => 16 bytes)
    round_keys: List[bytes] = []
    for r in range(Nr + 1):
        rk_words = w[r * Nb : (r + 1) * Nb]
        round_keys.append(words_to_bytes(rk_words))
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