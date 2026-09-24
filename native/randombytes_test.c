/* SPDX-License-Identifier: MIT
 * Test-only injectable entropy. This file is never compiled into release
 * packages.
 */
#include <stddef.h>
#include <stdint.h>

#define KPQC_JOIN_(left, right) left##right
#define KPQC_JOIN(left, right) KPQC_JOIN_(left, right)
#define KPQC_API(name) KPQC_JOIN(KPQC_PREFIX, name)

typedef int (*kpqc_entropy_callback)(uint8_t *output, size_t length);
static kpqc_entropy_callback callback;

void KPQC_API(set_randombytes)(kpqc_entropy_callback value) {
    callback = value;
}

static int kpqc_fill_random(uint8_t *output, size_t length) {
    return callback == NULL ? -1 : callback(output, length);
}

#if defined(KPQC_AIMER)
int randombytes(unsigned char *output, unsigned long long length) {
    if (length > (unsigned long long)SIZE_MAX) return -1;
    return kpqc_fill_random(output, (size_t)length);
}
#else
int randombytes(uint8_t *output, size_t length) {
    return kpqc_fill_random(output, length);
}
#endif
