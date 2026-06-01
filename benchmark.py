# =============================================================================
# What does this measure?
#   The execution time overhead introduced by the two modifications:
#     [MOD 1] Extra S-Box pass on the last word of each round key group
#     [MOD 2] Inter-round XOR feedback across all round keys
#
# Why does this matter?
#   Any cryptographic improvement has a cost — processing time.
#   We need to quantify exactly how much slower our modified version is.
#   If the overhead is small (e.g. <10%), the security gain is worth it.
#
# How we measure it:
#   Python's timeit module runs each function thousands of times and
#   returns the total elapsed time — giving a highly accurate average.
#
# Output:
#   - Average time per key expansion (microseconds)
#   - Overhead introduced by modifications (%)
#   - Throughput (keys expanded per second)
# =============================================================================

import timeit
import random
import statistics
from core.standard_aes import key_expansion
from core.modified_aes import modified_key_expansion


# -------------------------------------------------------------------------
# Helper: generate_random_keys
# -------------------------------------------------------------------------
def generate_random_keys(n=1000):
    return [[random.randint(0, 255) for _ in range(16)] for _ in range(n)]


# -------------------------------------------------------------------------
# MAIN FUNCTION: run_benchmark
# -------------------------------------------------------------------------
# Benchmarks both key schedules using timeit for accurate measurement.
#
# Parameters:
#   num_keys   : number of keys to expand per trial
#   num_trials : number of trials to run (for statistical accuracy)
# -------------------------------------------------------------------------
def run_benchmark(num_keys=1000, num_trials=10):
    keys = generate_random_keys(num_keys)

    std_times = []
    mod_times = []

    for trial in range(num_trials):
        # --- Benchmark Standard AES ---
        start = timeit.default_timer()
        for key in keys:
            key_expansion(key)
        end = timeit.default_timer()
        std_times.append(end - start)

        # --- Benchmark Modified AES ---
        start = timeit.default_timer()
        for key in keys:
            modified_key_expansion(key)
        end = timeit.default_timer()
        mod_times.append(end - start)

        print(f"  Trial {trial + 1:02d}/{num_trials} — "
              f"Std: {std_times[-1]*1000:.2f}ms  "
              f"Mod: {mod_times[-1]*1000:.2f}ms")

    return std_times, mod_times, num_keys


# -------------------------------------------------------------------------
# Helper: print_benchmark_report
# -------------------------------------------------------------------------
def print_benchmark_report(std_times, mod_times, num_keys):
    # Calculate statistics
    std_mean   = statistics.mean(std_times)
    mod_mean   = statistics.mean(mod_times)
    std_stdev  = statistics.stdev(std_times)
    mod_stdev  = statistics.stdev(mod_times)

    # Per-key timings in microseconds
    std_per_key = (std_mean / num_keys) * 1_000_000
    mod_per_key = (mod_mean / num_keys) * 1_000_000

    # Overhead
    overhead_pct = ((mod_mean - std_mean) / std_mean) * 100

    # Throughput (keys per second)
    std_throughput = num_keys / std_mean
    mod_throughput = num_keys / mod_mean

    print("\n" + "=" * 62)
    print("   PERFORMANCE BENCHMARK REPORT")
    print("=" * 62)
    print(f"\n  Keys per trial  : {num_keys:,}")
    print(f"  Trials run      : {len(std_times)}")
    print(f"  Total keys      : {num_keys * len(std_times):,}")

    print("\n" + "-" * 62)
    print(f"  {'Metric':<30} {'Standard':>12} {'Modified':>12}")
    print("-" * 62)
    print(f"  {'Mean time (ms/trial)':<30} {std_mean*1000:>11.3f}  {mod_mean*1000:>11.3f}")
    print(f"  {'Std deviation (ms)':<30} {std_stdev*1000:>11.3f}  {mod_stdev*1000:>11.3f}")
    print(f"  {'Time per key (µs)':<30} {std_per_key:>11.3f}  {mod_per_key:>11.3f}")
    print(f"  {'Throughput (keys/sec)':<30} {std_throughput:>11,.0f}  {mod_throughput:>11,.0f}")
    print("-" * 62)
    print(f"\n  Overhead introduced by modifications : {overhead_pct:+.2f}%")

    if overhead_pct < 10:
        verdict = "ACCEPTABLE — security gain outweighs the cost"
    elif overhead_pct < 25:
        verdict = "MODERATE — justified by cryptographic improvements"
    else:
        verdict = "HIGH — consider optimizing the modifications"

    print(f"  Verdict                              : {verdict}")

    # Visual bar comparison
    print("\n" + "-" * 62)
    print("  Relative Speed Comparison")
    print("-" * 62)
    max_time  = max(std_mean, mod_mean)
    std_bar   = int((std_mean / max_time) * 40)
    mod_bar   = int((mod_mean / max_time) * 40)
    print(f"  Standard  {'█' * std_bar} {std_mean*1000:.3f}ms")
    print(f"  Modified  {'█' * mod_bar} {mod_mean*1000:.3f}ms")
    print("=" * 62)


# -------------------------------------------------------------------------
# Run when executed directly
# -------------------------------------------------------------------------
if __name__ == "__main__":
    NUM_KEYS   = 1000
    NUM_TRIALS = 10

    print(f"\n  Running performance benchmark...")
    print(f"  {NUM_KEYS:,} keys × {NUM_TRIALS} trials\n")

    std_times, mod_times, num_keys = run_benchmark(NUM_KEYS, NUM_TRIALS)

    print_benchmark_report(std_times, mod_times, num_keys)