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

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    psa_key_id_t peer_key;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    status = psa_generate_key(&attributes, &peer_key);
    if (status != PSA_SUCCESS) { printf("Peer keygen failed: %d\n", status); return 1; }
    status = psa_export_public_key(peer_key, peer_public, sizeof(peer_public), &pub_len);
    if (status != PSA_SUCCESS) { printf("Peer export failed: %d\n", status); return 1; }

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
