from typing import List

from AES_core import aes_encrypt_block, aes_decrypt_block, xor_bytes


BLOCK_SIZE = 16

def pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("Invalid block size")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(padded) == 0 or (len(padded) % block_size) != 0:
        raise ValueError("Invalid padded length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding value")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return padded[:-pad_len]

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:
    if len(data) % block_size != 0:
        raise ValueError("Data length must be multiple of block size")
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")

    pt = pad(plaintext, BLOCK_SIZE)
    blocks = split_blocks(pt, BLOCK_SIZE)

    out = bytearray()
    prev = iv
    for blk in blocks:
        x = xor_bytes(blk, prev)
        c = aes_encrypt_block(key, x, trace=False)
        out.extend(c)
        prev = c
    return bytes(out)

def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if len(ciphertext) == 0 or (len(ciphertext) % BLOCK_SIZE) != 0:
        raise ValueError("Ciphertext length must be a positive multiple of 16 bytes")

    blocks = split_blocks(ciphertext, BLOCK_SIZE)

    out = bytearray()
    prev = iv
    for c in blocks:
        x = aes_decrypt_block(key, c, trace=False)
        p = xor_bytes(x, prev)
        out.extend(p)
        prev = c

    return unpad(bytes(out), BLOCK_SIZE)

def cbc_encrypt_file_format(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Returns: IV || CBC_encrypt(key, iv, plaintext)
    (Encrypted file is 1 block longer because it prepends IV.)
    """
    ct = cbc_encrypt(key, iv, plaintext)
    return iv + ct

def cbc_decrypt_file_format(key: bytes, iv_plus_ciphertext: bytes) -> bytes:
    """
    Expects: IV || ciphertext
    Uses first block as IV for decryption.
    """
    if len(iv_plus_ciphertext) < BLOCK_SIZE or (len(iv_plus_ciphertext) % BLOCK_SIZE) != 0:
        raise ValueError("Encrypted file must be at least 1 block and a multiple of 16 bytes")
    iv = iv_plus_ciphertext[:BLOCK_SIZE]
    ct = iv_plus_ciphertext[BLOCK_SIZE:]
    return cbc_decrypt(key, iv, ct)
