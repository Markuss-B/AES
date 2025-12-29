from AES_core import hex_to_bytes, aes_encrypt_block, aes_decrypt_block

def read_operation() -> str:
    """
    Returns "encrypt" or "decrypt".
    """
    while True:
        s = input("Darbības izvēle (šifrēt/atšifrēt) (1/2): ").strip().lower()

        if s in {"šifrēt", "sifret", "1", "s", "e"}:
            return "encrypt"
        if s in {"atšifrēt", "atsifret", "2", "a", "d"}:
            return "decrypt"

        print("Kļūda: ievadi 'šifrēt' vai 'atšifrēt' (1 vai 2).")

def read_hex_16_bytes(prompt: str) -> bytes:
    """
    Reads exactly 16 bytes as 32 hex chars.
    """
    while True:
        s = input(prompt).strip()
        try:
            b = hex_to_bytes(s)
            return b
        except Exception as ex:
            print(f"Kļūda: jāievada tieši 32 heksadecimālie simboli (0-9, a-f). ({ex})")

def main() -> None:
    op = read_operation()

    key = read_hex_16_bytes(
        "128 bitu atslēga (32 hex, 0-9 a-f):\n"
    )

    block = read_hex_16_bytes(
        "Šifrējamais/atšifrējamais 128 bitu datu bloks (32 hex, 0-9 a-f):\n"
    )

    if op == "encrypt":
        out = aes_encrypt_block(key, block, trace=False)
        print("Nošifrētais 128 bitu datu bloks (32 hex):")
    else:
        out = aes_decrypt_block(key, block, trace=False)
        print("Atšifrētais 128 bitu datu bloks (32 hex):")

    print(out.hex())

if __name__ == "__main__":
    main()