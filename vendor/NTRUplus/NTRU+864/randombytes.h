#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

/* KpqC bindings propagate failures from the operating-system entropy source. */
int randombytes(uint8_t *out, size_t outlen);

#endif
