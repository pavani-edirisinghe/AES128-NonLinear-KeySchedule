# =============================================================================
# What are NIST tests?
#   The NIST SP 800-22 test suite is the gold standard for testing whether
#   a sequence of bits is truly random. If a key schedule produces biased
#   or patterned bits, these tests will catch it.
#
# Why does this matter?
#   A good key schedule should produce round keys that look completely
#   random — no patterns, no bias, no repeating sequences.
#   If the keystream passes all NIST tests, it means an attacker cannot
#   distinguish it from pure random noise.
#
# Tests implemented (SP 800-22 subset):
#   1. Monobit Frequency Test     — Are 0s and 1s roughly equal?
#   2. Block Frequency Test       — Are blocks of bits balanced?
#   3. Runs Test                  — Are there too many/few runs of 0s and 1s?
#   4. Serial Test                — Are 2-bit patterns equally distributed?
#   5. Entropy Test               — How much information is in the bitstream?
#
# How we generate the bitstream:
#   Generate many random keys → expand each → concatenate all round key bits
#   → run NIST tests on the resulting bitstream
#
# Pass/Fail:
#   Each test produces a p-value. p-value >= 0.01 → PASS (random enough)
#   p-value <  0.01 → FAIL (statistically non-random)
# =============================================================================

import random
import math
from core.standard_aes import key_expansion
from core.modified_aes import modified_key_expansion


# -------------------------------------------------------------------------
# Helper: generate_bitstream
# -------------------------------------------------------------------------
# Generates a long bitstream by expanding many random keys and
# concatenating all the resulting round key bits.
# -------------------------------------------------------------------------
def generate_bitstream(expand_fn, num_keys=1000):
    bits = []
    for _ in range(num_keys):
        key = [random.randint(0, 255) for _ in range(16)]
        round_keys = expand_fn(key)
        for rk in round_keys:
            for byte in rk:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)
    return bits


# -------------------------------------------------------------------------
# TEST 1: Monobit Frequency Test
# -------------------------------------------------------------------------
# Checks if the number of 1s and 0s in the bitstream are roughly equal.
# A perfectly random sequence should have exactly 50% ones.
#
# p-value >= 0.01 → PASS
# -------------------------------------------------------------------------
def monobit_test(bits):
    n    = len(bits)
    s    = sum(1 if b == 1 else -1 for b in bits)   # convert 0→-1, 1→+1
    sobs = abs(s) / math.sqrt(n)
    # erfc = complementary error function (approximated)
    p_value = math.erfc(sobs / math.sqrt(2))
    return p_value


# -------------------------------------------------------------------------
# TEST 2: Block Frequency Test
# -------------------------------------------------------------------------
# Divides the bitstream into blocks of M bits.
# Tests whether the proportion of 1s in each block is close to 0.5.
#
# p-value >= 0.01 → PASS
# -------------------------------------------------------------------------
def block_frequency_test(bits, block_size=128):
    n          = len(bits)
    num_blocks = n // block_size
    chi_sq     = 0.0

    for i in range(num_blocks):
        block    = bits[i * block_size : (i + 1) * block_size]
        prop     = sum(block) / block_size
        chi_sq  += (prop - 0.5) ** 2

    chi_sq  *= 4 * block_size
    # Use chi-squared distribution with num_blocks degrees of freedom
    # Approximate p-value using the regularized incomplete gamma function
    p_value  = _igamc(num_blocks / 2, chi_sq / 2)
    return p_value


# -------------------------------------------------------------------------
# TEST 3: Runs Test
# -------------------------------------------------------------------------
# A "run" is an unbroken sequence of identical bits (e.g. 000 or 111).
# Tests whether the number of runs is consistent with a random sequence.
# Too many or too few runs indicates patterns.
#
# p-value >= 0.01 → PASS
# -------------------------------------------------------------------------
def runs_test(bits):
    n    = len(bits)
    pi   = sum(bits) / n              # proportion of 1s

    # Pre-condition: if pi is too far from 0.5, test is invalid
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return 0.0                    # automatic fail

    # Count runs (transitions between 0 and 1)
    runs = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])

    # Compute p-value
    num   = abs(runs - 2 * n * pi * (1 - pi))
    denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(num / denom)
    return p_value


# -------------------------------------------------------------------------
# TEST 4: Serial Test (2-bit patterns)
# -------------------------------------------------------------------------
# Checks if all 2-bit patterns (00, 01, 10, 11) appear equally often.
# In a truly random sequence, each should appear ~25% of the time.
#
# p-value >= 0.01 → PASS
# -------------------------------------------------------------------------
def serial_test(bits):
    n       = len(bits)
    counts  = {(0,0): 0, (0,1): 0, (1,0): 0, (1,1): 0}

    for i in range(n - 1):
        pair = (bits[i], bits[i + 1])
        counts[pair] += 1

    total   = sum(counts.values())
    chi_sq  = sum((c - total / 4) ** 2 / (total / 4) for c in counts.values())
    p_value = _igamc(3 / 2, chi_sq / 2)    # 3 degrees of freedom for 4 patterns
    return p_value


# -------------------------------------------------------------------------
# TEST 5: Approximate Entropy Test
# -------------------------------------------------------------------------
# Measures how much entropy (randomness) is in the bitstream.
# Higher entropy = more random = better key schedule.
# Returns entropy as bits-per-bit (ideal = 1.0 for truly random).
# -------------------------------------------------------------------------
def entropy_test(bits):
    n = len(bits)

    # Count frequency of each byte value in the bitstream
    # (group bits into bytes for entropy calculation)
    byte_counts = {}
    for i in range(0, n - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1

    total   = sum(byte_counts.values())
    entropy = 0.0
    for count in byte_counts.values():
        p        = count / total
        entropy -= p * math.log2(p)

    # Normalize to bits-per-bit (max entropy for bytes = 8 bits)
    normalized = entropy / 8.0
    # Convert to p-value style: 1.0 = perfect, 0.0 = no entropy
    return normalized


# -------------------------------------------------------------------------
# Helper: Regularized Incomplete Gamma Function (approximation)
# Used for chi-squared p-value calculations
# -------------------------------------------------------------------------
def _igamc(a, x):
    if x < 0 or a <= 0:
        return 1.0
    # Use series expansion approximation
    try:
        return 1.0 - _igam(a, x)
    except:
        return 0.0


def _igam(a, x):
    # Lower incomplete gamma via series
    if x == 0:
        return 0.0
    ap  = a
    val = 1.0 / a
    s   = val
    for _ in range(200):
        ap  += 1
        val *= x / ap
        s   += val
        if abs(val) < abs(s) * 1e-10:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


# -------------------------------------------------------------------------
# Helper: print_nist_report
# -------------------------------------------------------------------------
def print_nist_report(std_results, mod_results):
    tests = ["Monobit Frequency", "Block Frequency", "Runs Test",
             "Serial Test", "Entropy Test"]

    print("\n" + "=" * 70)
    print("   NIST SP 800-22 STATISTICAL RANDOMNESS TEST REPORT")
    print("=" * 70)
    print(f"  {'Test':<22} {'Standard':>12} {'Pass?':>6}  {'Modified':>12} {'Pass?':>6}")
    print("-" * 70)

    std_passes = 0
    mod_passes = 0

    for i, test in enumerate(tests):
        sv = std_results[i]
        mv = mod_results[i]

        if test == "Entropy Test":
            # Entropy: show as score, pass if > 0.95
            s_pass = "PASS" if sv > 0.95 else "FAIL"
            m_pass = "PASS" if mv > 0.95 else "FAIL"
            print(f"  {test:<22} {sv:>11.4f}  {s_pass:>6}  {mv:>11.4f}  {m_pass:>6}")
        else:
            # p-value tests: pass if >= 0.01
            s_pass = "PASS" if sv >= 0.01 else "FAIL"
            m_pass = "PASS" if mv >= 0.01 else "FAIL"
            print(f"  {test:<22} {sv:>11.4f}  {s_pass:>6}  {mv:>11.4f}  {m_pass:>6}")

        if (sv >= 0.01 if test != "Entropy Test" else sv > 0.95):
            std_passes += 1
        if (mv >= 0.01 if test != "Entropy Test" else mv > 0.95):
            mod_passes += 1

    print("-" * 70)
    print(f"  {'Total Tests Passed':<22} {std_passes:>12} {'/ 5':>6}  {mod_passes:>12} {'/ 5':>6}")
    print("=" * 70)
    print(f"\n  Note: p-value >= 0.01 = PASS (sequence is statistically random)")
    print(f"        Entropy score > 0.95 = PASS (high randomness)")

    better = "Modified" if mod_passes >= std_passes else "Standard"
    print(f"\n  Overall better randomness: {better} AES")
    print("=" * 70)


# -------------------------------------------------------------------------
# Run when executed directly
# -------------------------------------------------------------------------
if __name__ == "__main__":
    NUM_KEYS = 1000

    print(f"\n  Running NIST SP 800-22 statistical tests...")
    print(f"  Generating bitstream from {NUM_KEYS} random keys each...")
    print("  Please wait...\n")

    random.seed(99)

    print("  [1/2] Generating Standard AES bitstream...")
    std_bits = generate_bitstream(key_expansion, NUM_KEYS)

    print("  [2/2] Generating Modified AES bitstream...")
    mod_bits = generate_bitstream(modified_key_expansion, NUM_KEYS)

    print(f"\n  Bitstream length: {len(std_bits):,} bits each\n")

    print("  Running tests...")
    std_results = [
        monobit_test(std_bits),
        block_frequency_test(std_bits),
        runs_test(std_bits),
        serial_test(std_bits),
        entropy_test(std_bits),
    ]
    mod_results = [
        monobit_test(mod_bits),
        block_frequency_test(mod_bits),
        runs_test(mod_bits),
        serial_test(mod_bits),
        entropy_test(mod_bits),
    ]

    print_nist_report(std_results, mod_results)