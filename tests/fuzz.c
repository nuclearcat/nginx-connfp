/* SPDX-License-Identifier: BSD-2-Clause */
/* clang -g -fsanitize=fuzzer,address,undefined -I src tests/fuzz.c \
 *   src/connfp.c -lcrypto -o /tmp/connfp-fuzz
 * /tmp/connfp-fuzz -max_total_time=30 -max_len=131072 /tmp/connfp-corpus */
#include "connfp.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char tls[CONNFP_TLS_SIZE], syn[CONNFP_SYN_SIZE];
    (void)connfp_tls(data, size, tls);
    (void)connfp_syn(data, size, syn);
    return 0;
}

#ifdef CONNFP_FUZZ_STANDALONE
#include <stdio.h>
#include <string.h>
/* Reproducible mutation runner when libFuzzer/clang is unavailable. Supply
 * well-formed ClientHello and SYN seed files as command-line arguments. */
static uint32_t state = 1729;
static uint32_t random_word(void)
{
    state ^= state << 13; state ^= state >> 17; state ^= state << 5;
    return state;
}
int main(int argc, char **argv)
{
    uint8_t seed[131072], data[131072];
    size_t n, len, i, j;
    int file;
    for (file = 1; file < argc; ++file) {
        FILE *input = fopen(argv[file], "rb");
        if (!input) return 1;
        n = fread(seed, 1, sizeof(seed), input);
        fclose(input);
        LLVMFuzzerTestOneInput(seed, n);
        for (i = 0; i < 100000; ++i) {
            memcpy(data, seed, n);
            len = i % 4 == 0 ? random_word() % (n + 1) : n;
            for (j = 0; j < 1 + i % 8; ++j) {
                if (len) data[random_word() % len] = (uint8_t)random_word();
            }
            LLVMFuzzerTestOneInput(data, len);
        }
    }
    puts("PASS: 100,000 sanitized mutations per seed");
    return 0;
}
#endif
