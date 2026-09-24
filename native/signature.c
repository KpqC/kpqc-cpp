/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdint.h>
#include "api.h"

#define KPQC_JOIN_(left, right) left##right
#define KPQC_JOIN(left, right) KPQC_JOIN_(left, right)
#define KPQC_API(name) KPQC_JOIN(KPQC_PREFIX, name)

int KPQC_API(keypair)(uint8_t *public_key, uint8_t *secret_key) {
    return crypto_sign_keypair(public_key, secret_key);
}

int KPQC_API(sign)(uint8_t *signature, size_t *signature_len,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *context, size_t context_len,
                   const uint8_t *secret_key) {
    return crypto_sign_signature(signature, signature_len, message, message_len,
                                 context, context_len, secret_key);
}

int KPQC_API(verify)(const uint8_t *signature, size_t signature_len,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *context, size_t context_len,
                     const uint8_t *public_key) {
    return crypto_sign_verify(signature, signature_len, message, message_len,
                              context, context_len, public_key);
}
