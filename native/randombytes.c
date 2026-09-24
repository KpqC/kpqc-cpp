/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#include <limits.h>
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
#include <stdlib.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <errno.h>
#include <sys/random.h>
#else
#error "kpqc currently supports operating-system entropy on Windows, Linux, Android, macOS, and BSD"
#endif

static int kpqc_fill_random(uint8_t *output, size_t length) {
#if defined(_WIN32)
    while (length != 0) {
        ULONG chunk = length > (size_t)ULONG_MAX ? ULONG_MAX : (ULONG)length;
        if (BCryptGenRandom(NULL, output, chunk,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            return -1;
        }
        output += chunk;
        length -= chunk;
    }
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
    arc4random_buf(output, length);
    return 0;
#else
    while (length != 0) {
        ssize_t count = getrandom(output, length, 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        output += (size_t)count;
        length -= (size_t)count;
    }
    return 0;
#endif
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
