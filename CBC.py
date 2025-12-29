from pathlib import Path

from CBC_core import cbc_encrypt_file_format, cbc_decrypt_file_format
from AES import read_hex_16_bytes, read_operation

def read_path(prompt: str) -> Path:
    while True:
        p = Path(input(prompt).strip())
        if str(p) == "":
            print("Kļūda: tukšs ceļš.")
            continue
        return p


def main() -> None:
    op = read_operation()

    key = read_hex_16_bytes(
        "128 bitu atslēga (32 hex, 0-9 a-f):\n"
    )

    if op == "encrypt":
        iv = read_hex_16_bytes(
            "128 bitu inicializācijas vektors IV (32 hex):\n"
        )
    else:
        iv = b""  # not used; IV is taken from encrypted file's first block

    in_path = read_path("Šifrējamais (atšifrējamais) fails:\nNorāde uz failu: ")
    out_path = read_path("Nošifrētais (atšifrētais) fails:\nNorāde uz failu: ")

    data = in_path.read_bytes()

    try:
        if op == "encrypt":
            out = cbc_encrypt_file_format(key, iv, data)
        else:
            out = cbc_decrypt_file_format(key, data)

        out_path.write_bytes(out)
        print("Gatavs.")
        print(f"Ievade:  {in_path}")
        print(f"Izvade:  {out_path}")
        if op == "encrypt":
            print("Atgādinājums: nošifrētais fails ir par 1 bloku garāks (pirmais bloks ir IV).")
    except Exception as ex:
        print(f"Kļūda: {ex}")

if __name__ == "__main__":
    main()
