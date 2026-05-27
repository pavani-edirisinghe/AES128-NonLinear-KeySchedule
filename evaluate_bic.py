# =============================================================================
# What is BIC?
#   The Bit Independence Criterion states that:
#   "When a single input bit is flipped, any two different output bits
#    should change INDEPENDENTLY of each other."
#
# Why does this matter?
#   If output bit A and output bit B always flip together (or never together),
#   an attacker can learn information about one bit from the other.
#   True independence means knowing one output bit tells you NOTHING
#   about another — making statistical attacks much harder.
#
# How we measure it:
#   For every pair of output bits (i, j):
#     1. Flip one input bit at a time
#     2. Record whether output bit i changed (0 or 1)
#     3. Record whether output bit j changed (0 or 1)
#     4. Compute their correlation coefficient
#        → Ideal: correlation = 0.0 (completely independent)
#        → Bad  : correlation = ±1.0 (completely dependent)
#
#   BIC Score = average |correlation| across all bit pairs
#   Lower BIC score = better independence = stronger cipher
# =============================================================================

import random
import math
from core.standard_aes import key_expansion
from core.modified_aes import modified_key_expansion


def bytes_to_bits(byte_list):
    bits = []
    for byte in byte_list:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def flip_bit(key, bit_pos):
    flipped = key[:]
    byte_index = bit_pos // 8
    bit_index  = 7 - (bit_pos % 8)
    flipped[byte_index] ^= (1 << bit_index)
    return flipped


# -------------------------------------------------------------------------
# Helper: pearson_correlation
# -------------------------------------------------------------------------
# Computes the Pearson correlation coefficient between two binary sequences.
# Result ranges from -1 to +1.
# 0 = independent, ±1 = fully dependent.
# -------------------------------------------------------------------------
def pearson_correlation(x, y):
    n    = len(x)
    mx   = sum(x) / n
    my   = sum(y) / n
    num  = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    dx   = math.sqrt(sum((xi - mx) ** 2 for xi in x))
    dy   = math.sqrt(sum((yi - my) ** 2 for yi in y))
    if dx == 0 or dy == 0:
        return 0.0
    return num / (dx * dy)


# -------------------------------------------------------------------------
# MAIN FUNCTION: evaluate_bic
# -------------------------------------------------------------------------
# Tests BIC by checking independence between pairs of output bits.
#
# To keep runtime reasonable, we sample a subset of bit pairs
# rather than testing all 1408×1408 combinations.
#
# Parameters:
#   expand_fn  : key_expansion or modified_key_expansion
#   num_keys   : number of random keys to test
#   num_pairs  : number of random output bit pairs to sample
#
# Returns:
#   avg_bic    : average absolute correlation (lower = better)
#   near_zero  : % of pairs with |correlation| < 0.1 (higher = better)
# -------------------------------------------------------------------------
def evaluate_bic(expand_fn, num_keys=200, num_pairs=200):
    total_output_bits = 11 * 16 * 8    # 1408 bits total across all round keys

    # Pre-select random pairs of output bit positions to test
    random.seed(42)                    # fixed seed for reproducibility
    pairs = [(random.randint(0, total_output_bits - 1),
              random.randint(0, total_output_bits - 1))
             for _ in range(num_pairs)]
    # Make sure we don't test a bit against itself
    pairs = [(a, b) for a, b in pairs if a != b][:num_pairs]

    # For each pair, collect change vectors across all keys and input bit flips
    # change_vectors[pair_idx] = (list of bit_i changes, list of bit_j changes)
    pair_x = [[] for _ in range(len(pairs))]
    pair_y = [[] for _ in range(len(pairs))]

    for _ in range(num_keys):
        key = [random.randint(0, 255) for _ in range(16)]

        # Get original round key bits
        orig_bits = bytes_to_bits([b for rk in expand_fn(key) for b in rk])

        # Flip each input bit
        for in_bit in range(128):
            flipped_key  = flip_bit(key, in_bit)
            flipped_bits = bytes_to_bits([b for rk in expand_fn(flipped_key) for b in rk])

            # Record which output bits changed (1=changed, 0=unchanged)
            changes = [orig_bits[k] ^ flipped_bits[k] for k in range(total_output_bits)]

            # Record change for each sampled pair
            for idx, (a, b) in enumerate(pairs):
                pair_x[idx].append(changes[a])
                pair_y[idx].append(changes[b])

    # Compute correlation for each pair
    correlations = []
    for idx in range(len(pairs)):
        corr = pearson_correlation(pair_x[idx], pair_y[idx])
        correlations.append(abs(corr))

    avg_bic   = sum(correlations) / len(correlations)
    near_zero = sum(1 for c in correlations if c < 0.1) / len(correlations) * 100

    return avg_bic, near_zero, correlations


# -------------------------------------------------------------------------
# Helper: print_bic_report
# -------------------------------------------------------------------------
def print_bic_report(std_bic, mod_bic, std_nz, mod_nz, std_corr, mod_corr):
    print("\n" + "=" * 60)
    print("   BIT INDEPENDENCE CRITERION (BIC) EVALUATION REPORT")
    print("=" * 60)
    print(f"\n  Ideal BIC Score (avg |correlation|) : 0.0000")
    print(f"  Standard AES avg |correlation|      : {std_bic:.4f}")
    print(f"  Modified AES avg |correlation|      : {mod_bic:.4f}")

    better = "Modified" if mod_bic < std_bic else "Standard"
    improvement = ((std_bic - mod_bic) / std_bic * 100) if std_bic > 0 else 0

    print(f"\n  Pairs near-independent (<0.1) Standard : {std_nz:.1f}%")
    print(f"  Pairs near-independent (<0.1) Modified : {mod_nz:.1f}%")
    print(f"\n  Better BIC performance                 : {better} AES")
    if better == "Modified":
        print(f"  Improvement over standard              : {improvement:.1f}%")

    print("\n" + "-" * 60)
    print("  Correlation Distribution")
    print("-" * 60)

    # Bucket correlations into ranges
    buckets = {"0.0–0.1": 0, "0.1–0.2": 0, "0.2–0.3": 0, "0.3+": 0}
    for label, corrs in [("Standard", std_corr), ("Modified", mod_corr)]:
        counts = {"0.0–0.1": 0, "0.1–0.2": 0, "0.2–0.3": 0, "0.3+": 0}
        for c in corrs:
            if   c < 0.1: counts["0.0–0.1"] += 1
            elif c < 0.2: counts["0.1–0.2"] += 1
            elif c < 0.3: counts["0.2–0.3"] += 1
            else:         counts["0.3+"]    += 1
        total = len(corrs)
        print(f"\n  {label} AES:")
        for bucket, count in counts.items():
            pct = count / total * 100
            bar = "█" * int(pct / 2)
            print(f"    |corr| {bucket:>8} : {count:>4} pairs ({pct:>5.1f}%)  {bar}")

    print("\n" + "=" * 60)


def save_csv(std_corr, mod_corr, filename="bic_results.csv"):
    with open(filename, "w") as f:
        f.write("pair_index,standard_abs_corr,modified_abs_corr\n")
        for i, (s, m) in enumerate(zip(std_corr, mod_corr)):
            f.write(f"{i},{s:.4f},{m:.4f}\n")
    print(f"\n  Results saved to {filename}")


if __name__ == "__main__":
    NUM_KEYS  = 200
    NUM_PAIRS = 200

    print(f"\n  Running BIC evaluation...")
    print(f"  Keys per test : {NUM_KEYS}")
    print(f"  Bit pairs     : {NUM_PAIRS}")
    print("  Please wait...\n")

    print("  [1/2] Evaluating Standard AES...")
    std_bic, std_nz, std_corr = evaluate_bic(key_expansion, NUM_KEYS, NUM_PAIRS)

    print("  [2/2] Evaluating Modified AES...")
    mod_bic, mod_nz, mod_corr = evaluate_bic(modified_key_expansion, NUM_KEYS, NUM_PAIRS)

    print_bic_report(std_bic, mod_bic, std_nz, mod_nz, std_corr, mod_corr)

    # Uncomment to save full CSV:
    # save_csv(std_corr, mod_corr)