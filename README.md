# Projekta struktūra
- AES_tables.py – Rijndael SBOX, INV_SBOX un RCON konstantes. 
- AES_core.py – AES-128: datu pārveidojumi, KeyExpansion, šifrēšana/atšifrēšana un raunda operācijas.
- AES.py – lietotāja saskarne AES blokam. 
- CBC_core.py – CBC, padding/unpadding.
- CBC.py – lietotāja saskarne CBC failiem. 
- test_*.py un debug.py - testi un debugging

# Palaišana

AES: py AES.py

CBC: py CBC.py

Testi: py -m unittest -v

# Uzdevums un prasības
Jārealizē divas programmas bez gataviem kriptogrāfiskiem bibliotēku moduļiem:  
1. **AES-128 bitu bloku šifrs**
    1. Darbības izvēle *šifrēt/atšifrēt* (1/2)
    2. Ievada 128 bitu atslēgu kā 32 heksadecimālus simbolus
    3. Ievada 128 bitu bloku kā 32 heksadecimālus simbolus
    4. Izvada rezultātu kā 32 heksadecimālus simbolus
2. **CBC failu šifrs** Izmanto AES kā bloku šifru
    1. Darbības izvēle *šifrēt/atšifrēt* (1/2)
    2. Ievada 128 bitu atslēgu kā 32 heksadecimālus simbolus
    3. Ievada IV (tikai šifrēšanas režīmā) ka 32 heksadecimālus simbolus
    4. Ievada ieavdes faila ceļu un izvades faila ceļu.
    5. Nošifrētais fails ir par 1 bloku garāks, jo pirmais bloks ir IV.

Kā algoritmiskie pamati tiek izmantoti lekciju materiāli par AES un failu šifriem un FIPS-197 pseido-kods un kontrolpiemēri.

# Datu attēlojums un baitu izvietojums (State)
AES 128 bitu bloks un atslēga tiek apstrādāti kā 16 baiti un ievietoti 4×4 stāvokļa masīvā state[row][col]. Izvietojums atbilst lekcijā dotajam un FIPS-197: state[r][c] = in[r + 4*c] (kolonnu-major).

Ievade/izvade CLI līmenī notiek heksadecimāli: 32 simboli {0..9,a..f} → 16 baiti. 

# AES-128 realizācija

## Raundu atslēgu ģenerēšana (key_expansion_128)
Tiek realizēts FIPS-197 `KeyExpansion` algoritms AES-128 gadījumam ar parametriem `Nk=4`, `Nb=4`, `Nr=10`.
Atslēga tiek sadalīta vārdos `w0..w3`, un ģenerēti `w0..w43`, no kuriem izveido 11 raundu atslēgas (round 0..10). Lekcijā aprakstītā funkcija (RotWord + SubWord + XOR ar RC) tiek izmantota šai ģenerācijai.

## Šifrēšana (aes_encrypt_block)
Šifrēšana atbilst FIPS-197 `Cipher()` pseido-kodam: sākumā `AddRoundKey`, tad 9 raundi ar `SubBytes → ShiftRows → MixColumns → AddRoundKey`, un pēdējais raunds bez `MixColumns`.

Realizētās raunda funkcijas:
- `AddRoundKey`: XOR pa baitiem starp stāvokli un raunda atslēgu.
- `SubBytes`: aizvietošana ar Rijndael S-box tabulu.
- `ShiftRows`: 2., 3., 4. rindu cikliska nobīde pa kreisi par 1/2/3.
- `MixColumns`: lineāra transformācija katrai kolonnai ar konstantēm `{02}` un `{03}` Rijndael laukā; reizinājums ar `{02}` tiek realizēts ar `xtime`, bet `{03}*x = xtime(x) xor x` (tātad `xtime` pielieto 1 reizi).

## Dešifrēšana (aes_decrypt_block)
Dešifrēšana atbilst FIPS-197 `InvCipher()` pseido-kodam: sākas ar `AddRoundKey` ar pēdējo raunda atslēgu, tad raundi ar `InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns`, un beigās `InvShiftRows → InvSubBytes → AddRoundKey`.

Inverse operācijas:
- `InvShiftRows`: cikliska nobīde pa labi par 1/2/3.
- `InvSubBytes`: inverse S-box tabula.
- `InvMixColumns`: formulas ar `{09},{0b},{0d},{0e}`. Reizinājumi tiek realizēti, izmantojot tikai 3 `xtime` (aprēķina `x2, x4, x8` un kombinē ar XOR), kā tas ieteikts lekcijā.

# CBC/AES failu šifrs

## Padding
Tā kā fails var nebūt bloka daudzkārtnis, pirms šifrēšanas tiek pielietots padding veids: **“papildināt skaitli katrā baitā, kas norāda pievienojamo simbolu skaitu”** (Bruce Schneier ieteiktais variants). 
Atšifrējot tiek veikts `unpad` (pārbauda pēdējā baita vērtību un pēdējo baitu vienādību).

## CBC ķēdēšana
CBC režīms tiek realizēts kā “cipher block chaining”, balstoties uz failu šifru lekcijas ideju par bloku ķēdēšanu un IV izmantošanu.

Jā, tā var izskatīties mulsinoši, jo dešifrēšanā parādās **AES⁻¹** un “iepriekšējais šifrbloks”. Vienkāršākais veids ir uzrakstīt to kā 2 soļus katram blokam.

### CBC šifrēšana (2 soļi katram blokam)

`C0 = IV`.

Katram blokam `i = 1..m`:

1. **XOR ar iepriekšējo šifrbloku**:
   `Xi = Pi ⊕ C_{i-1}`
2. **Šifrē ar AES**:
   `Ci = AES_K(Xi)`

### CBC atšifrēšana (2 soļi katram blokam)

`C0 = IV`.

Katram blokam `i = 1..m`:

1. **Atšifrē ar AES**:
   `Xi = AES^{-1}_K(Ci)`
2. **XOR ar iepriekšējo šifrbloku**:
   `Pi = Xi ⊕ C_{i-1}`

## Faila formāts ar IV pirmajā blokā
Atbilstoši prasībai šifrētais fails tiek veidots kā:
- `IV || C1 || C2 || ...`, tātad šifrētais fails ir par 1 bloku garāks (pirmais bloks ir IV). 
Dešifrēšanas režīmā IV netiek prasīts no lietotāja — tas tiek nolasīts no šifrētā faila pirmā bloka.

# Lietotāja saskarne

## `AES.py` (1 bloka šifrēšana/dešifrēšana)
- Lietotājs izvēlas darbību (*šifrēt/atšifrēt*) (1/2), ievada 32 hex atslēgu un 32 hex datu bloku.  
- Programma izvada 32 hex rezultātu.
## `CBC.py` (failu šifrēšana/dešifrēšana)
- Šifrēšana: lietotājs ievada atslēgu + IV, norāda ievades failu un izvades failu.  
- Dešifrēšana: lietotājs ievada atslēgu, norāda šifrēto failu (kur pirmais bloks ir IV) un izvades failu.

Fails tiek apstrādāts kā “jebkāda tipa baitu virkne” (read/write bytes), tāpēc var šifrēt jebkuru formātu.