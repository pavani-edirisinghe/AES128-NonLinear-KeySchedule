# =============================================================================
# What this file does:
#   Takes a 128-bit (16-byte) secret key and "expands" it into 11 round keys
#   (each 128-bit), which AES uses during encryption and decryption.
#
# Why key expansion?
#   AES has 10 rounds of encryption. Each round needs its own unique key.
#   The key schedule is the algorithm that generates all 11 round keys from
#   the one original key you provide.
# =============================================================================


# -------------------------------------------------------------------------
# AES S-Box (Substitution Box)
# -------------------------------------------------------------------------
# This is a fixed 256-entry lookup table. It replaces each byte with another
# byte in a non-linear way. This is what gives AES its confusion property.
# Think of it like a secret codebook: input byte → output byte.
# -------------------------------------------------------------------------
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# -------------------------------------------------------------------------
# Round Constants (RCON)
# -------------------------------------------------------------------------
# Each of the 10 rounds uses a unique constant to prevent symmetry between
# rounds. These are pre-calculated values based on powers of 2 in GF(2^8).
# Without RCON, rounds 1 and 2 would produce similar subkeys — dangerous!
# -------------------------------------------------------------------------
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]


# -------------------------------------------------------------------------
# Helper: sub_word
# -------------------------------------------------------------------------
# Takes a 4-byte word (list of 4 integers) and applies the S-Box to each byte.
# Example: [0x00, 0xFF, 0xAB, 0x12] → [S[0x00], S[0xFF], S[0xAB], S[0x12]]
# -------------------------------------------------------------------------
def sub_word(word):
    return [S_BOX[b] for b in word]


# -------------------------------------------------------------------------
# Helper: rot_word
# -------------------------------------------------------------------------
# Rotates a 4-byte word left by 1 byte (cyclic shift).
# Example: [a, b, c, d] → [b, c, d, a]
# This breaks up the byte positions so subkeys aren't too predictable.
# -------------------------------------------------------------------------
def rot_word(word):
    return word[1:] + word[:1]


# -------------------------------------------------------------------------
# Helper: xor_words
# -------------------------------------------------------------------------
# XORs two 4-byte words together byte by byte.
# XOR is the core mixing operation in AES — it's reversible and fast.
# -------------------------------------------------------------------------
def xor_words(w1, w2):
    return [a ^ b for a, b in zip(w1, w2)]


# -------------------------------------------------------------------------
# MAIN FUNCTION: key_expansion (Standard AES-128)
# -------------------------------------------------------------------------
# Input : key → a list of 16 bytes (your 128-bit original secret key)
# Output: round_keys → a list of 11 round keys, each 16 bytes
#
# How it works:
#   AES-128 works with "words" — groups of 4 bytes.
#   A 128-bit key = 4 words = W[0], W[1], W[2], W[3]
#   We expand this to 44 words total (11 round keys × 4 words each).
#
#   For each new word W[i]:
#     - If i is a multiple of 4 (start of a new round key):
#         W[i] = W[i-4] XOR SubWord(RotWord(W[i-1])) XOR RCON[i/4 - 1]
#     - Otherwise:
#         W[i] = W[i-4] XOR W[i-1]
# -------------------------------------------------------------------------
def key_expansion(key):
    # Step 1: Make sure the key is exactly 16 bytes
    assert len(key) == 16, "AES-128 requires a 16-byte key!"

    # Step 2: Split the key into 4 initial words (W[0] to W[3])
    # Each word = 4 bytes
    words = []
    for i in range(4):
        word = key[4*i : 4*i + 4]   # grab bytes i*4 to i*4+3
        words.append(word)

    # Step 3: Generate the remaining 40 words (W[4] to W[43])
    for i in range(4, 44):
        temp = words[i - 1]          # start with the previous word

        if i % 4 == 0:
            # --- Core transformation (applied every 4 words) ---
            # 1. RotWord: rotate bytes left → [b1,b2,b3,b0]
            temp = rot_word(temp)
            # 2. SubWord: apply S-Box to each byte
            temp = sub_word(temp)
            # 3. XOR with round constant (only first byte of RCON matters)
            rcon_word = [RCON[i // 4 - 1], 0x00, 0x00, 0x00]
            temp = xor_words(temp, rcon_word)

        # XOR with the word 4 positions back
        new_word = xor_words(words[i - 4], temp)
        words.append(new_word)

    # Step 4: Group the 44 words into 11 round keys (4 words each = 16 bytes)
    round_keys = []
    for i in range(11):
        round_key = []
        for w in words[i*4 : i*4 + 4]:
            round_key.extend(w)       # flatten 4 words → 16 bytes
        round_keys.append(round_key)

    return round_keys


# -------------------------------------------------------------------------
# Helper: pretty_print_keys
# -------------------------------------------------------------------------
# Prints all round keys in a readable hex format for inspection/debugging.
# -------------------------------------------------------------------------
def pretty_print_keys(round_keys):
    print("=" * 55)
    print("  AES-128 Standard Key Schedule — Round Keys")
    print("=" * 55)
    for i, rk in enumerate(round_keys):
        hex_str = ' '.join(f'{b:02X}' for b in rk)
        print(f"  Round Key {i:02d}: {hex_str}")
    print("=" * 55)


# -------------------------------------------------------------------------
# Run a quick demo when this file is executed directly
# -------------------------------------------------------------------------
if __name__ == "__main__":
    # FIPS 197 standard test vector — known correct output you can verify online
    test_key = [
        0x2B, 0x7E, 0x15, 0x16,
        0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,
        0x09, 0xCF, 0x4F, 0x3C,
    ]

    print("\nOriginal Key:")
    print(" ", ' '.join(f'{b:02X}' for b in test_key))
    print()

    round_keys = key_expansion(test_key)
    pretty_print_keys(round_keys)

    print(f"\nTotal round keys generated: {len(round_keys)}")
    print("Each round key is 16 bytes (128 bits).")
    print("\nRound Key 0 should match original key:")
    print(" ", round_keys[0] == test_key)