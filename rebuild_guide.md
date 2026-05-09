# Complete Rebuild Guide: Mbed TLS 4.0.0 Optimized Build on Raspberry Pi 4

## Project Context

M.Tech Part-II project: "Accelerating and Securing the Edge: A TrustZone-Backed TLS 1.3 Gateway"
- Platform: Raspberry Pi 4, BCM2711, Cortex-A72 @ 1.5GHz, ARMv8-A, **NO hardware crypto extensions**
- Software: Mbed TLS 4.0.0, GCC 14.2.0
- Build flags: `-O2 -march=armv8-a -mtune=cortex-a72` (**NEVER use `+crypto`** — causes SIGILL)
- Three functions optimized in `bignum_core.c` with ARM64 inline assembly
- Result: 11.1% fewer handshake cycles, 15.8% fewer instructions, `mpi_core_sub` overhead 23% → 1.69%

---

## Step 0: Flash and Setup Raspberry Pi OS

1. Download Raspberry Pi OS 64-bit from the official site
2. Flash to SD card using Raspberry Pi Imager
3. Set username: `abhishek`, set password, enable SSH
4. Boot Pi, connect via Ethernet to your OptiPlex
5. Find Pi IP: `nmap -sn 10.42.0.0/24`
6. SSH in: `ssh abhishek@<pi_ip>`

---

## Step 1: Install Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential cmake git python3 perl openssl libssl-dev linux-perf
```

---

## Step 2: Clone Mbed TLS 4.0.0

```bash
cd ~
git clone --branch v4.0.0 --recurse-submodules https://github.com/ARMmbed/mbedtls.git
cd mbedtls
```

---

## Step 3: Apply Code Optimizations

**CRITICAL: All changes go in one file:**
`~/mbedtls/tf-psa-crypto/drivers/builtin/src/bignum_core.c`

First, back it up:

```bash
cp tf-psa-crypto/drivers/builtin/src/bignum_core.c \
   tf-psa-crypto/drivers/builtin/src/bignum_core.c.backup
```

Now edit the file:

```bash
nano tf-psa-crypto/drivers/builtin/src/bignum_core.c
```

### CHANGE 1: Replace `mbedtls_mpi_core_sub`

Find this function (search for `mbedtls_mpi_core_sub`). Replace the ENTIRE function with:

```c
mbedtls_mpi_uint mbedtls_mpi_core_sub(mbedtls_mpi_uint *X,
                                      const mbedtls_mpi_uint *A,
                                      const mbedtls_mpi_uint *B,
                                      size_t limbs)
{
    mbedtls_mpi_uint c = 0;

#if defined(__aarch64__)
    if (limbs > 0) {
        mbedtls_mpi_uint *x_ptr = X;
        const mbedtls_mpi_uint *a_ptr = A;
        const mbedtls_mpi_uint *b_ptr = B;
        size_t count = limbs;
        uint64_t tmp_a, tmp_b;

        __asm__ __volatile__ (
            /* Set carry flag to 1 (no borrow) for first SBCS */
            "cmp    xzr, xzr                \n\t"

            "1:                             \n\t"
            "ldr    %[tmp_a], [%[a_ptr]], #8 \n\t"
            "ldr    %[tmp_b], [%[b_ptr]], #8 \n\t"
            "sbcs   %[tmp_a], %[tmp_a], %[tmp_b] \n\t"
            "str    %[tmp_a], [%[x_ptr]], #8 \n\t"

            "sub    %[count], %[count], #1   \n\t"
            "cbnz   %[count], 1b             \n\t"

            /* Extract borrow: C=0 means borrow occurred, so c=1 */
            "cset   %[c], cc                 \n\t"

            : [c] "=r" (c),
              [a_ptr] "+r" (a_ptr), [b_ptr] "+r" (b_ptr),
              [x_ptr] "+r" (x_ptr), [count] "+r" (count),
              [tmp_a] "=&r" (tmp_a), [tmp_b] "=&r" (tmp_b)
            :
            : "cc", "memory"
        );
    }
#else
    for (size_t i = 0; i < limbs; i++) {
        mbedtls_mpi_uint z = mbedtls_ct_mpi_uint_if(mbedtls_ct_uint_lt(A[i], c),
                                                    1, 0);
        mbedtls_mpi_uint t = A[i] - c;
        c = mbedtls_ct_mpi_uint_if(mbedtls_ct_uint_lt(t, B[i]), 1, 0) + z;
        X[i] = t - B[i];
    }
#endif

    return c;
}
```

**Why this works:** ARM64 `SBCS` does subtract-with-borrow in 1 instruction per limb, replacing ~6 C operations. `SUB`/`CBNZ` for loop control preserves the carry flag. `CMP xzr,xzr` initializes carry=1 (no borrow). Inherently constant-time.

---

### CHANGE 2: Replace `mbedtls_mpi_core_add`

Find this function. Replace the ENTIRE function with:

```c
mbedtls_mpi_uint mbedtls_mpi_core_add(mbedtls_mpi_uint *X,
                                      const mbedtls_mpi_uint *A,
                                      const mbedtls_mpi_uint *B,
                                      size_t limbs)
{
    mbedtls_mpi_uint c = 0;

#if defined(__aarch64__)
    if (limbs > 0) {
        mbedtls_mpi_uint *x_ptr = X;
        const mbedtls_mpi_uint *a_ptr = A;
        const mbedtls_mpi_uint *b_ptr = B;
        size_t count = limbs;
        uint64_t tmp_a, tmp_b;

        __asm__ __volatile__ (
            /* Clear carry flag */
            "adds   xzr, xzr, xzr           \n\t"

            "1:                              \n\t"
            "ldr    %[tmp_a], [%[a_ptr]], #8 \n\t"
            "ldr    %[tmp_b], [%[b_ptr]], #8 \n\t"
            "adcs   %[tmp_a], %[tmp_a], %[tmp_b] \n\t"
            "str    %[tmp_a], [%[x_ptr]], #8 \n\t"

            "sub    %[count], %[count], #1   \n\t"
            "cbnz   %[count], 1b             \n\t"

            /* Extract carry */
            "cset   %[c], cs                 \n\t"

            : [c] "=r" (c),
              [a_ptr] "+r" (a_ptr), [b_ptr] "+r" (b_ptr),
              [x_ptr] "+r" (x_ptr), [count] "+r" (count),
              [tmp_a] "=&r" (tmp_a), [tmp_b] "=&r" (tmp_b)
            :
            : "cc", "memory"
        );
    }
#else
    for (size_t i = 0; i < limbs; i++) {
        mbedtls_mpi_uint t = c + A[i];
        c = (t < A[i]);
        t += B[i];
        c += (t < B[i]);
        X[i] = t;
    }
#endif

    return c;
}
```

**Why this works:** Same pattern as sub but using `ADCS` (add with carry) and `ADDS xzr,xzr,xzr` to clear carry initially. `CSET cs` extracts carry (cs = carry set).

---

### CHANGE 3: Replace `mbedtls_mpi_core_mla`

Find this function. Replace the ENTIRE function with:

```c
mbedtls_mpi_uint mbedtls_mpi_core_mla(mbedtls_mpi_uint *d, size_t d_len,
                                      const mbedtls_mpi_uint *s, size_t s_len,
                                      mbedtls_mpi_uint b)
{
    mbedtls_mpi_uint c = 0;
    if (d_len < s_len) { s_len = d_len; }
    size_t excess_len = d_len - s_len;

#if defined(__aarch64__)
    if (s_len > 0) {
        mbedtls_mpi_uint *s_ptr = (mbedtls_mpi_uint *)s;
        mbedtls_mpi_uint *d_ptr = d;

        /* Process pairs of limbs (2 at a time) */
        size_t pairs = s_len / 2;
        size_t remaining = s_len % 2;

        if (pairs > 0) {
            uint64_t ts0, ts1, td0, td1, lo0, hi0, lo1, hi1;
            size_t cnt = pairs;

            __asm__ __volatile__ (
                "1:                                  \n\t"
                /* Load both source and dest limbs */
                "ldr    %[ts0], [%[sp]], #8          \n\t"
                "ldr    %[ts1], [%[sp]], #8          \n\t"
                "ldr    %[td0], [%[dp]]              \n\t"
                "ldr    %[td1], [%[dp], #8]          \n\t"

                /* Issue all 4 multiplies upfront — CPU can pipeline these */
                "mul    %[lo0], %[ts0], %[b]         \n\t"
                "umulh  %[hi0], %[ts0], %[b]         \n\t"
                "mul    %[lo1], %[ts1], %[b]         \n\t"
                "umulh  %[hi1], %[ts1], %[b]         \n\t"

                /* Limb 0: d[i] += s[i]*b + carry */
                "adds   %[td0], %[td0], %[c]        \n\t"
                "adcs   %[c],   %[hi0], xzr          \n\t"
                "adds   %[td0], %[td0], %[lo0]       \n\t"
                "adc    %[c],   %[c],   xzr          \n\t"
                "str    %[td0], [%[dp]], #8          \n\t"

                /* Limb 1: d[i+1] += s[i+1]*b + carry */
                "adds   %[td1], %[td1], %[c]        \n\t"
                "adcs   %[c],   %[hi1], xzr          \n\t"
                "adds   %[td1], %[td1], %[lo1]       \n\t"
                "adc    %[c],   %[c],   xzr          \n\t"
                "str    %[td1], [%[dp]], #8          \n\t"

                "subs   %[cnt], %[cnt], #1           \n\t"
                "b.ne   1b                           \n\t"

                : [c] "+r" (c), [sp] "+r" (s_ptr), [dp] "+r" (d_ptr),
                  [cnt] "+r" (cnt),
                  [ts0] "=&r" (ts0), [ts1] "=&r" (ts1),
                  [td0] "=&r" (td0), [td1] "=&r" (td1),
                  [lo0] "=&r" (lo0), [hi0] "=&r" (hi0),
                  [lo1] "=&r" (lo1), [hi1] "=&r" (hi1)
                : [b] "r" (b)
                : "cc", "memory"
            );
        }

        /* Handle remaining odd limb */
        if (remaining) {
            uint64_t ts, td, lo, hi;
            __asm__ __volatile__ (
                "ldr    %[ts], [%[sp]], #8           \n\t"
                "ldr    %[td], [%[dp]]               \n\t"
                "mul    %[lo], %[ts], %[b]           \n\t"
                "umulh  %[hi], %[ts], %[b]           \n\t"
                "adds   %[td], %[td], %[c]           \n\t"
                "adcs   %[c],  %[hi], xzr            \n\t"
                "adds   %[td], %[td], %[lo]          \n\t"
                "adc    %[c],  %[c],  xzr            \n\t"
                "str    %[td], [%[dp]], #8           \n\t"
                : [c] "+r" (c), [sp] "+r" (s_ptr), [dp] "+r" (d_ptr),
                  [ts] "=&r" (ts), [td] "=&r" (td),
                  [lo] "=&r" (lo), [hi] "=&r" (hi)
                : [b] "r" (b)
                : "cc", "memory"
            );
        }

        d = d_ptr;
    }
#else
    for (size_t i = 0; i < s_len; i++) {
        unsigned __int128 r = (unsigned __int128) s[i] * b + d[i] + c;
        d[i] = (mbedtls_mpi_uint) r;
        c = (mbedtls_mpi_uint) (r >> 64);
    }
    d += s_len;
#endif

    while (excess_len--) {
        *d += c;
        c = mbedtls_ct_mpi_uint_if(mbedtls_ct_uint_lt(*d, c), 1, 0);
        d++;
    }

    return c;
}
```

**Why this works:** `MUL`+`UMULH` gives precise 64×64→128-bit multiplication. 2-limb unrolling issues all 4 multiplies upfront so Cortex-A72's pipelined multiply unit can overlap limb 1's multiplies with limb 0's carry chain. Odd remaining limb handled separately.

---

## Step 4: Build

```bash
cd ~/mbedtls
mkdir build && cd build

cmake .. \
    -DCMAKE_C_FLAGS="-O2 -march=armv8-a -mtune=cortex-a72" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTING=ON \
    -DENABLE_PROGRAMS=ON

make -j4
```

**⚠️ NEVER use `-march=armv8-a+crypto` — BCM2711 lacks crypto extensions, causes SIGILL crashes.**

---

## Step 5: Verify Correctness

```bash
ctest -R "bignum" --output-on-failure 2>&1 | tail -15
```

Must show: `9/9 tests passed, 0 tests failed`

---

## Step 6: Create Custom ECDH Benchmark

```bash
cat > ~/mbedtls/test_ecdh_bench.c << 'HEREDOC'
#include <stdio.h>
#include <time.h>
#include "psa/crypto.h"

int main(void) {
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t our_key;
    uint8_t peer_public[65], our_public[65], shared_secret[32];
    size_t pub_len, secret_len;
    int count = 0;
    clock_t start, end;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) { printf("Init failed: %d\n", status); return 1; }

    /* Setup key attributes for ECDH with P-256 */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    /* Generate a "peer" key to simulate the other side */
    psa_key_id_t peer_key;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    status = psa_generate_key(&attributes, &peer_key);
    if (status != PSA_SUCCESS) { printf("Peer keygen failed: %d\n", status); return 1; }
    status = psa_export_public_key(peer_key, peer_public, sizeof(peer_public), &pub_len);
    if (status != PSA_SUCCESS) { printf("Peer export failed: %d\n", status); return 1; }

    /* Benchmark: generate our key + compute shared secret */
    printf("Benchmarking ECDH-P256 (keygen + key agreement)...\n");
    start = clock();
    while ((clock() - start) < 3 * CLOCKS_PER_SEC) {
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        status = psa_generate_key(&attributes, &our_key);
        if (status != PSA_SUCCESS) break;

        status = psa_raw_key_agreement(PSA_ALG_ECDH,
            our_key, peer_public, pub_len,
            shared_secret, sizeof(shared_secret), &secret_len);
        psa_destroy_key(our_key);
        if (status != PSA_SUCCESS) break;
        count++;
    }
    end = clock();

    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("ECDH-P256: %d operations in %.2f seconds = %.1f ops/s\n",
           count, elapsed, count / elapsed);

    /* Now benchmark X25519 */
    count = 0;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attributes, 255);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    status = psa_generate_key(&attributes, &peer_key);
    if (status != PSA_SUCCESS) { printf("X25519 peer keygen failed: %d\n", status); return 1; }
    status = psa_export_public_key(peer_key, peer_public, sizeof(peer_public), &pub_len);
    if (status != PSA_SUCCESS) { printf("X25519 peer export failed: %d\n", status); return 1; }

    printf("Benchmarking ECDH-X25519 (keygen + key agreement)...\n");
    start = clock();
    while ((clock() - start) < 3 * CLOCKS_PER_SEC) {
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        status = psa_generate_key(&attributes, &our_key);
        if (status != PSA_SUCCESS) break;

        status = psa_raw_key_agreement(PSA_ALG_ECDH,
            our_key, peer_public, pub_len,
            shared_secret, sizeof(shared_secret), &secret_len);
        psa_destroy_key(our_key);
        if (status != PSA_SUCCESS) break;
        count++;
    }
    end = clock();

    elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("ECDH-X25519: %d operations in %.2f seconds = %.1f ops/s\n",
           count, elapsed, count / elapsed);

    psa_destroy_key(peer_key);
    mbedtls_psa_crypto_free();
    return 0;
}
HEREDOC
```

Compile it:

```bash
cd ~/mbedtls

gcc -O2 -march=armv8-a -mtune=cortex-a72 \
    -I build/tf-psa-crypto/include \
    -I tf-psa-crypto/include \
    -I tf-psa-crypto/drivers/builtin/include \
    -I include \
    test_ecdh_bench.c \
    -L build/library -lmbedcrypto \
    -o test_ecdh_bench
```

---

## Step 7: Generate TLS Test Certs

```bash
cd ~/mbedtls/build
openssl ecparam -genkey -name prime256v1 -out server_ec.key
openssl req -new -x509 -key server_ec.key -out server_ec.crt -days 365 -subj "/CN=localhost"
```

---

## Step 8: Run All Benchmarks

```bash
cd ~/mbedtls

# Full benchmark suite
./build/tf-psa-crypto/programs/test/benchmark 2>&1 | tee ~/benchmark_results.txt

# ECDH benchmark
./test_ecdh_bench

# TLS handshake (ECDHE + ECDSA only)
cd build
sudo fuser -k 4433/tcp 2>/dev/null; sleep 2
./programs/ssl/ssl_server2 crt_file=server_ec.crt key_file=server_ec.key \
    server_port=4433 auth_mode=none \
    force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 > /dev/null 2>&1 &
sleep 3
sudo perf stat -e cycles,instructions \
    ./programs/ssl/ssl_client2 server_name=localhost server_port=4433 \
    auth_mode=optional crt_file=none key_file=none \
    force_ciphersuite=TLS1-3-AES-128-GCM-SHA256
sudo fuser -k 4433/tcp 2>/dev/null

# TLS data transfer AES-GCM
sudo fuser -k 4433/tcp 2>/dev/null; sleep 2
./programs/ssl/ssl_server2 crt_file=server_ec.crt key_file=server_ec.key \
    server_port=4433 exchanges=100 auth_mode=optional \
    force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 > /dev/null 2>&1 &
sleep 3
echo "=== AES-GCM ===" > ~/tls_results.txt
sudo perf stat -e cycles,instructions \
    ./programs/ssl/ssl_client2 server_name=localhost server_port=4433 \
    exchanges=100 request_size=16384 auth_mode=optional \
    force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 >> ~/tls_results.txt 2>&1
sudo fuser -k 4433/tcp 2>/dev/null; sleep 2

# TLS data transfer ChaCha20
./programs/ssl/ssl_server2 crt_file=server_ec.crt key_file=server_ec.key \
    server_port=4433 exchanges=100 auth_mode=optional \
    force_ciphersuite=TLS1-3-CHACHA20-POLY1305-SHA256 > /dev/null 2>&1 &
sleep 3
echo "=== ChaCha20 ===" >> ~/tls_results.txt
sudo perf stat -e cycles,instructions \
    ./programs/ssl/ssl_client2 server_name=localhost server_port=4433 \
    exchanges=100 request_size=16384 auth_mode=optional \
    force_ciphersuite=TLS1-3-CHACHA20-POLY1305-SHA256 >> ~/tls_results.txt 2>&1
sudo fuser -k 4433/tcp 2>/dev/null

grep -E "===|cycles|instructions|elapsed" ~/tls_results.txt
```

---

## Step 9: Profiling

```bash
cd ~/mbedtls/build
sudo fuser -k 4433/tcp 2>/dev/null; sleep 2
./programs/ssl/ssl_server2 crt_file=server_ec.crt key_file=server_ec.key \
    server_port=4433 auth_mode=none \
    force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 > /dev/null 2>&1 &
sleep 3
sudo perf record -g --call-graph dwarf \
    ./programs/ssl/ssl_client2 server_name=localhost server_port=4433 \
    auth_mode=optional crt_file=none key_file=none \
    force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 > /dev/null 2>&1
sudo fuser -k 4433/tcp 2>/dev/null
sudo perf report --stdio --no-children --sort=symbol --no-call-graph > ~/profile_optimized.txt
cat ~/profile_optimized.txt
```

---

## Expected Results After Rebuild

| Metric | Baseline (original C) | Optimized (our asm) |
|---|---|---|
| Handshake cycles | ~21.6M | ~19.2M (**11.1% fewer**) |
| Handshake instructions | ~32.3M | ~27.2M (**15.8% fewer**) |
| `mpi_core_sub` overhead | 16-23% | ~1.7% (**12x reduction**) |
| ECDH-X25519 | ~320 ops/s | ~322 ops/s |
| ECDH-P256 | ~311 ops/s | ~313 ops/s |
| AES-GCM-128 throughput | 44,131 KiB/s | same |
| ChaCha20-Poly1305 throughput | 81,130 KiB/s | same |
| Bignum tests | - | 9/9 pass |

---

## Important Reminders

1. **NEVER use `-march=armv8-a+crypto`** — BCM2711 lacks crypto hardware, causes SIGILL
2. **Always regenerate certs** after `rm -rf build` — they're stored inside the build directory
3. **Wait 3 seconds** after starting `ssl_server2` before running `ssl_client2`
4. **Use `sudo fuser -k 4433/tcp`** to kill any lingering server before starting a new one
5. **The only file modified** is `tf-psa-crypto/drivers/builtin/src/bignum_core.c` — three functions replaced with `#if defined(__aarch64__)` guarded inline assembly
6. **To get baseline numbers**, build once WITHOUT the code changes (use the `.backup` file), run benchmarks, then apply changes and rebuild for optimized numbers

---

## Why ARM64 Scalar Assembly, Not NEON

- NEON lacks 64×64→128-bit multiply (only 32×32→64)
- Carry/borrow propagation is inherently serial (each limb depends on previous)
- NEON↔GP register transfer costs 2-3 cycles
- ARM64 scalar `SBCS` does subtract-with-borrow in 1 insn/limb
- `MUL`+`UMULH` gives precise 128-bit products
- NEON useful for: ChaCha20 (already uses it), curve-specific P-256 field reduction, symmetric ciphers

---

## Files That Will Be Created on Pi

- `~/benchmark_results.txt` — full Mbed TLS benchmark output
- `~/tls_results.txt` — AES-GCM vs ChaCha20 data transfer comparison
- `~/profile_optimized.txt` — perf function-level profile
- `~/mbedtls/test_ecdh_bench.c` — custom ECDH benchmark source
- `~/mbedtls/test_ecdh_bench` — compiled ECDH benchmark binary
- `~/mbedtls/tf-psa-crypto/drivers/builtin/src/bignum_core.c.backup` — original unmodified code