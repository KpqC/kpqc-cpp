#include "registry.hpp"

#include <cstddef>
#include <cstdint>

extern "C" {

#define KPQC_DECLARE_SIGNATURE(name)                                          \
    int kpqc_##name##_keypair(std::uint8_t*, std::uint8_t*);                 \
    int kpqc_##name##_sign(                                                   \
        std::uint8_t*, std::size_t*, const std::uint8_t*, std::size_t,        \
        const std::uint8_t*, std::size_t, const std::uint8_t*);               \
    int kpqc_##name##_verify(                                                 \
        const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,   \
        const std::uint8_t*, std::size_t, const std::uint8_t*)

KPQC_DECLARE_SIGNATURE(aimer128f);
KPQC_DECLARE_SIGNATURE(aimer128s);
KPQC_DECLARE_SIGNATURE(aimer192f);
KPQC_DECLARE_SIGNATURE(aimer192s);
KPQC_DECLARE_SIGNATURE(aimer256f);
KPQC_DECLARE_SIGNATURE(aimer256s);

#undef KPQC_DECLARE_SIGNATURE
}

namespace kpqc::aimer {

#define KPQC_ACCESSOR(accessor, algorithm_id, public_key_size,                \
                      secret_key_size, signature_size)                        \
    const SignatureAlgorithm& accessor() noexcept {                           \
        static const SignatureAlgorithm value = detail::Registry::signature( \
            algorithm_id,                                                     \
            {public_key_size, secret_key_size, signature_size},               \
            kpqc_##accessor##_keypair,                                        \
            kpqc_##accessor##_sign,                                           \
            kpqc_##accessor##_verify);                                        \
        return value;                                                         \
    }

KPQC_ACCESSOR(aimer128f, "aimer-128f", 32, 48, 6944)
KPQC_ACCESSOR(aimer128s, "aimer-128s", 32, 48, 4704)
KPQC_ACCESSOR(aimer192f, "aimer-192f", 48, 72, 15408)
KPQC_ACCESSOR(aimer192s, "aimer-192s", 48, 72, 10320)
KPQC_ACCESSOR(aimer256f, "aimer-256f", 64, 96, 31360)
KPQC_ACCESSOR(aimer256s, "aimer-256s", 64, 96, 20224)

#undef KPQC_ACCESSOR

}  // namespace kpqc::aimer
