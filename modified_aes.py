# =============================================================================
# What's different from standard AES?
#
#   MODIFICATION 1 — Extra S-Box Application:
#     In standard AES, SubWord() is only applied to W[i-1] when i % 4 == 0.
#     Here, we apply an EXTRA S-Box pass to the last word of each round key
#     AFTER it is generated. This increases non-linearity in every subkey word.
#
#   MODIFICATION 2 — Inter-Round XOR Feedback:
#     After each complete round key (every 4 words) is generated, we XOR
#     it with the PREVIOUS round key. This creates a dependency chain:
#     every round key is now influenced by all previous round keys.
#     In standard AES, only W[i-4] and W[i-1] influence W[i].
#
# Why does this help?
#   - More non-linearity → harder for attackers to solve algebraic equations
#     relating the original key to subkeys (related-key attack resistance)
#   - Inter-round feedback → a single bit flip in the original key now
#     propagates changes through ALL subsequent round keys more aggressively
#   - Both improvements are measurable via SAC, BIC, and NIST tests
#
# IMPORTANT: These modifications are applied ONLY to the key schedule.
#            The encryption/decryption data path is NOT changed.
#            The modified key schedule still produces 11 valid 16-byte round keys.
# =============================================================================

# Reuse the same S-Box and RCON from standard AES
# (copy them here so this file is self-contained)
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

RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]


# -------------------------------------------------------------------------
# Same helper functions as standard AES
# -------------------------------------------------------------------------
def sub_word(word):
    """Apply S-Box substitution to each byte of a 4-byte word."""
    return [S_BOX[b] for b in word]


def rot_word(word):
    """Rotate a 4-byte word left by 1 byte: [a,b,c,d] → [b,c,d,a]."""
    return word[1:] + word[:1]


def xor_words(w1, w2):
    """XOR two 4-byte words together byte by byte."""
    return [a ^ b for a, b in zip(w1, w2)]


def xor_round_keys(rk1, rk2):
    """XOR two full 16-byte round keys together byte by byte."""
    return [a ^ b for a, b in zip(rk1, rk2)]


# -------------------------------------------------------------------------
# MAIN FUNCTION: modified_key_expansion
# -------------------------------------------------------------------------
# Input : key → a list of 16 bytes (128-bit original secret key)
# Output: round_keys → a list of 11 round keys, each 16 bytes
#
# Differences from standard:
#   [MOD 1] After computing the 4th word of each new round key,
#            apply an extra S-Box pass to that word.
#   [MOD 2] After completing each round key (rounds 1–10),
#            XOR it with the previous round key.
# -------------------------------------------------------------------------
def modified_key_expansion(key):
    assert len(key) == 16, "AES-128 requires a 16-byte key!"

    # Step 1: Split key into 4 initial words
    words = []
    for i in range(4):
        words.append(key[4*i : 4*i + 4])

    # Step 2: Generate words W[4] through W[43]
    for i in range(4, 44):
        temp = words[i - 1]

        if i % 4 == 0:
            # Standard AES transformation
            temp = rot_word(temp)
            temp = sub_word(temp)
            rcon_word = [RCON[i // 4 - 1], 0x00, 0x00, 0x00]
            temp = xor_words(temp, rcon_word)

        new_word = xor_words(words[i - 4], temp)

        # ------------------------------------------------------------------
        # [MOD 1] Extra S-Box pass on the LAST word of each round key group
        # ------------------------------------------------------------------
        # In standard AES, SubWord is only used at position i % 4 == 0.
        # Here, when we finish the 4th word of any round key (i % 4 == 3),
        # we apply SubWord once more. This forces additional non-linearity
        # into the final word of every subkey, disrupting linearity.
        # ------------------------------------------------------------------
        if i % 4 == 3:
            new_word = sub_word(new_word)   # [MOD 1]

        words.append(new_word)

    # Step 3: Group into 11 round keys (same as standard)
    round_keys = []
    for i in range(11):
        round_key = []
        for w in words[i*4 : i*4 + 4]:
            round_key.extend(w)
        round_keys.append(round_key)

    # ------------------------------------------------------------------
    # [MOD 2] Inter-Round XOR Feedback
    # ------------------------------------------------------------------
    # After all round keys are built, XOR each round key (rounds 1–10)
    # with the PREVIOUS round key.
    #
    # Why not round 0? Round 0 IS the original key — we never modify it.
    # This ensures decryption can still recover the original key.
    #
    # Effect: Round Key N now carries information from ALL prior rounds,
    # not just round N-1. A single flipped input bit now cascades further.
    # ------------------------------------------------------------------
    for i in range(1, 11):
        round_keys[i] = xor_round_keys(round_keys[i], round_keys[i - 1])   # [MOD 2]

    return round_keys


# -------------------------------------------------------------------------
# Helper: pretty_print_keys
# -------------------------------------------------------------------------
def pretty_print_keys(round_keys, label="Modified"):
    print("=" * 55)
    print(f"  AES-128 {label} Key Schedule — Round Keys")
    print("=" * 55)
    for i, rk in enumerate(round_keys):
        hex_str = ' '.join(f'{b:02X}' for b in rk)
        print(f"  Round Key {i:02d}: {hex_str}")
    print("=" * 55)


# -------------------------------------------------------------------------
# Side-by-side comparison: show how much the keys differ
# -------------------------------------------------------------------------
def compare_keys(std_keys, mod_keys):
    from standard_aes import key_expansion  # import standard for comparison
    print("\n" + "=" * 55)
    print("  Comparison: Standard vs Modified Round Keys")
    print("=" * 55)
    print(f"  {'Round':<8} {'Bytes Different':>15} {'% Changed':>12}")
    print("-" * 55)
    total_diff = 0
    for i in range(11):
        diffs = sum(1 for a, b in zip(std_keys[i], mod_keys[i]) if a != b)
        pct = (diffs / 16) * 100
        total_diff += diffs
        print(f"  RK {i:02d}    {diffs:>15}     {pct:>10.1f}%")
    print("-" * 55)
    print(f"  Total bytes different: {total_diff} / {11*16}")
    print("=" * 55)


# -------------------------------------------------------------------------
# Run demo when executed directly
# -------------------------------------------------------------------------
if __name__ == "__main__":
    from standard_aes import key_expansion, pretty_print_keys as std_print

    test_key = [
        0x2B, 0x7E, 0x15, 0x16,
        0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,
        0x09, 0xCF, 0x4F, 0x3C,
    ]

    print("\nOriginal Key:")
    print(" ", ' '.join(f'{b:02X}' for b in test_key))

    # Generate both
    std_keys = key_expansion(test_key)
    mod_keys = modified_key_expansion(test_key)

    print("\n--- STANDARD ---")
    std_print(std_keys)

    print("\n--- MODIFIED ---")
    pretty_print_keys(mod_keys)

    # Show differences
    compare_keys(std_keys, mod_keys)

    print("\n[MOD 1] Extra S-Box applied to last word of each round key group.")
    print("[MOD 2] Inter-round XOR feedback applied to rounds 1–10.")
    print("\nRound Key 0 preserved (same as original key):", mod_keys[0] == test_key)