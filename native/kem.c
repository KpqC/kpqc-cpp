/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include "api.h"

#define KPQC_JOIN_(left, right) left##right
#define KPQC_JOIN(left, right) KPQC_JOIN_(left, right)
#define KPQC_API(name) KPQC_JOIN(KPQC_PREFIX, name)

int KPQC_API(keypair)(uint8_t *public_key, uint8_t *secret_key) {
    return crypto_kem_keypair(public_key, secret_key);
}

int KPQC_API(encapsulate)(uint8_t *ciphertext,
                          uint8_t *shared_secret,
                          const uint8_t *public_key) {
    return crypto_kem_enc(ciphertext, shared_secret, public_key);
}

int KPQC_API(decapsulate)(uint8_t *shared_secret,
                          const uint8_t *ciphertext,
                          const uint8_t *secret_key) {
    return crypto_kem_dec(shared_secret, ciphertext, secret_key);
}
