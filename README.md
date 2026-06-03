# AES-128 Enhanced Key Schedule

A research project proposing and validating two structural modifications to the AES-128 key expansion algorithm to improve non-linearity and avalanche properties.

---

## Problem Statement

The standard AES key expansion process uses a partially linear structure, making it theoretically vulnerable to related-key attacks. This project introduces two targeted modifications to the key schedule and mathematically proves their improvement using cryptographic evaluation metrics.

---

## Modifications

| | Modification | Description |
|---|---|---|
| MOD 1 | Extra S-Box Pass | Applies an additional S-Box substitution to the last word of each round key group, increasing non-linearity |
| MOD 2 | Inter-Round XOR Feedback | XORs each completed round key with the previous one, creating a dependency chain across all rounds |

---

## Project Structure

```
AES128-NonLinear-KeySchedule/
├── core/
│   ├── __init__.py
│   ├── standard_aes.py       # Baseline AES-128 key schedule (FIPS 197)
│   └── modified_aes.py       # Enhanced key schedule (MOD 1 + MOD 2)
├── evaluate_sac.py            # Strict Avalanche Criterion test
├── evaluate_bic.py            # Bit Independence Criterion test
├── evaluate_nist.py           # NIST SP 800-22 statistical tests
├── benchmark.py               # Performance benchmarking
└── main.py                    # Runs all evaluations and prints full report
```

---

## Results

### Strict Avalanche Criterion (SAC)
> A single flipped input bit should cause ~50% of output bits to change.

| | Standard AES | Modified AES | Ideal |
|---|---|---|---|
| SAC Score | 29.04% | **36.59%** | 50.00% |
| Deviation from ideal | 20.96% | **13.41%** | 0% |

Modified AES is **36% closer to ideal** than standard AES.

---

### Bit Independence Criterion (BIC)
> Output bits should change independently when any input bit is flipped.

| | Standard AES | Modified AES | Ideal |
|---|---|---|---|
| Avg \|correlation\| | 0.0504 | **0.0211** | 0.0000 |
| Near-independent pairs | 85.0% | **93.5%** | 100% |

Modified AES achieves **58.2% better bit independence**.

---

### NIST SP 800-22 Statistical Tests
> Keystream bits should be statistically indistinguishable from random noise.

| Test | Standard | Modified |
|---|---|---|
| Monobit Frequency | 0.1578 ✅ | **0.3375** ✅ |
| Block Frequency | 0.1800 ✅ | **0.2375** ✅ |
| Runs Test | 0.4665 ✅ | **0.7189** ✅ |
| Serial Test | 0.2106 ✅ | **0.5786** ✅ |
| Entropy Test | 0.9999 ✅ | **0.9999** ✅ |
| **Total Passed** | **5 / 5** | **5 / 5** |

Both pass all 5 tests. Modified AES scores higher p-values on 4 out of 5 tests.

---

### Performance Benchmark

| Metric | Standard AES | Modified AES |
|---|---|---|
| Time per key | 30.15 µs | 41.96 µs |
| Throughput | 33,169 keys/sec | 23,835 keys/sec |
| Overhead | — | +39.16% |

The overhead applies only to the key schedule, which runs **once per session**. The actual encryption throughput is unaffected. Given the measurable cryptographic improvements across all 4 metrics, this cost is fully justified.

---

## How to Run

**Requirements:** Python 3.8+, no external libraries needed.

```bash
# Clone the repository
git clone https://github.com/pavani-edirisinghe/AES128-NonLinear-KeySchedule.git
cd AES128-NonLinear-KeySchedule

# Run the full evaluation (all 4 tests + final summary)
python main.py

# Or run individual tests
python evaluate_sac.py
python evaluate_bic.py
python evaluate_nist.py
python benchmark.py
```

---

## Conclusion

The proposed modifications demonstrably improve the non-linearity and avalanche properties of the AES-128 key schedule across all cryptographic metrics, at an acceptable computational overhead confined to the key expansion phase.

---

*University of Ruhuna — Faculty of Engineering — Department of Electrical & Information Engineering*