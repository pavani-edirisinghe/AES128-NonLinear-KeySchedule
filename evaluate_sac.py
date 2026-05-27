# =============================================================================
# What is SAC?
#   The Strict Avalanche Criterion states that:
#   "If a single input bit is flipped, each output bit should change
#    with a probability of exactly 50%."
#
# Why does this matter?
#   If flipping 1 bit in the key causes ~50% of subkey bits to change,
#   it means the key schedule is highly sensitive and unpredictable.
#   An attacker cannot guess which output bits will change — ideal behavior.
#
# How we test it:
#   1. Generate a random 128-bit key
#   2. Expand it → get all 11 round keys (standard and modified)
#   3. Flip ONE bit in the original key (bit 0, then bit 1, ... bit 127)
#   4. Expand the flipped key → get new round keys
#   5. XOR original vs flipped round keys → count how many bits differ
#   6. Ideal result: ~50% of 1408 bits change (128 bits × 11 round keys)
#   7. Repeat for many random keys and average the results
#
# SAC Score:
#   score = (average bits changed) / (total bits) × 100%
#   Perfect SAC = 50.0%
#   Closer to 50% = better avalanche effect
# =============================================================================

import random
from standard_aes import key_expansion
from modified_aes import modified_key_expansion


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


def count_bit_differences(keys1, keys2):
    flat1 = [b for rk in keys1 for b in rk]
    flat2 = [b for rk in keys2 for b in rk]
    bits1 = bytes_to_bits(flat1)
    bits2 = bytes_to_bits(flat2)
    return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))


def evaluate_sac(expand_fn, num_keys=500):
    total_bits = 11 * 16 * 8
    bit_flip_scores = [0.0] * 128

    for _ in range(num_keys):
        key = [random.randint(0, 255) for _ in range(16)]
        original_keys = expand_fn(key)

        for bit_pos in range(128):
            flipped_key  = flip_bit(key, bit_pos)
            flipped_keys = expand_fn(flipped_key)
            diff_bits    = count_bit_differences(original_keys, flipped_keys)
            bit_flip_scores[bit_pos] += diff_bits / total_bits

    per_bit_avg = [score / num_keys for score in bit_flip_scores]
    avg_score   = sum(per_bit_avg) / 128
    return avg_score * 100, per_bit_avg


def print_sac_report(std_score, mod_score, std_per_bit, mod_per_bit):
    print("\n" + "=" * 60)
    print("   STRICT AVALANCHE CRITERION (SAC) EVALUATION REPORT")
    print("=" * 60)
    print(f"\n  Ideal SAC Score : 50.00%")
    print(f"  Standard AES    : {std_score:.4f}%")
    print(f"  Modified AES    : {mod_score:.4f}%")

    std_dev = abs(std_score - 50.0)
    mod_dev = abs(mod_score - 50.0)
    better  = "Modified" if mod_dev < std_dev else "Standard"

    print(f"\n  Deviation from ideal (Standard) : {std_dev:.4f}%")
    print(f"  Deviation from ideal (Modified) : {mod_dev:.4f}%")
    print(f"\n  Better SAC performance          : {better} AES")

    print("\n" + "-" * 60)
    print("  Per-Bit SAC Scores (first 16 bits shown)")
    print("-" * 60)
    print(f"  {'Bit':>4}  {'Standard':>10}  {'Modified':>10}  {'Winner':>10}")
    print("-" * 60)
    for i in range(16):
        std_pct = std_per_bit[i] * 100
        mod_pct = mod_per_bit[i] * 100
        winner  = "Modified" if abs(mod_pct - 50) < abs(std_pct - 50) else "Standard"
        print(f"  {i:>4}  {std_pct:>9.2f}%  {mod_pct:>9.2f}%  {winner:>10}")
    print("-" * 60)
    print("=" * 60)


def save_csv(std_per_bit, mod_per_bit, filename="sac_results.csv"):
    with open(filename, "w") as f:
        f.write("bit_position,standard_sac_%,modified_sac_%\n")
        for i in range(128):
            f.write(f"{i},{std_per_bit[i]*100:.4f},{mod_per_bit[i]*100:.4f}\n")
    print(f"\n  Results saved to {filename}")


if __name__ == "__main__":
    NUM_KEYS = 500

    print(f"\n  Running SAC evaluation on {NUM_KEYS} random keys...")
    print("  Testing all 128 bit-flip positions per key. Please wait...\n")

    print("  [1/2] Evaluating Standard AES...")
    std_score, std_per_bit = evaluate_sac(key_expansion, NUM_KEYS)

    print("  [2/2] Evaluating Modified AES...")
    mod_score, mod_per_bit = evaluate_sac(modified_key_expansion, NUM_KEYS)

    print_sac_report(std_score, mod_score, std_per_bit, mod_per_bit)

    # Uncomment to save full CSV:
    # save_csv(std_per_bit, mod_per_bit)