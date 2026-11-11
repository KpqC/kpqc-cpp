// SPDX-License-Identifier: MIT

#include "hash.h"
#include <stddef.h>
#include <stdint.h>

#if SECURITY_BITS == 128
#define shake_inc_init shake128_inc_init
#define shake_inc_absorb shake128_inc_absorb
#define shake_inc_final shake128_inc_finalize
#define shake_inc_squeeze shake128_inc_squeeze
#define shake_inc_ctx_release shake128_inc_ctx_release
#else
#define shake_inc_init shake256_inc_init
#define shake_inc_absorb shake256_inc_absorb
#define shake_inc_final shake256_inc_finalize
#define shake_inc_squeeze shake256_inc_squeeze
#define shake_inc_ctx_release shake256_inc_ctx_release
#endif

void hash_init(hash_instance *ctx)
{
  shake_inc_init(ctx);
}

void hash_init_prefix(hash_instance *ctx, uint8_t prefix)
{
  shake_inc_init(ctx);
  shake_inc_absorb(ctx, &prefix, sizeof(prefix));
}

void hash_update(hash_instance *ctx, const uint8_t *data, size_t data_len)
{
  shake_inc_absorb(ctx, data, data_len);
}

void hash_final(hash_instance *ctx)
{
  shake_inc_final(ctx);
}

void hash_squeeze(hash_instance *ctx, uint8_t *buffer, size_t buffer_len)
{
  shake_inc_squeeze(buffer, buffer_len, ctx);
}

void hash_update_gf(hash_instance *ctx, const gf *values, size_t count)
{
  uint8_t encoded[AIM3_NUM_BYTES_FIELD];

  for (size_t i = 0; i < count; i++)
  {
    gf_to_bytes(encoded, values[i]);
    hash_update(ctx, encoded, sizeof(encoded));
  }
}

void hash_squeeze_gf(hash_instance *ctx, gf *values, size_t count)
{
  uint8_t encoded[AIM3_NUM_BYTES_FIELD];

  for (size_t i = 0; i < count; i++)
  {
    hash_squeeze(ctx, encoded, sizeof(encoded));
    gf_from_bytes(values[i], encoded);
  }
}

void hash_ctx_release(hash_instance *ctx)
{
  shake_inc_ctx_release(ctx);
}
