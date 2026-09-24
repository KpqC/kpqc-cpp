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

KPQC_DECLARE_SIGNATURE(haetae2);
KPQC_DECLARE_SIGNATURE(haetae3);
KPQC_DECLARE_SIGNATURE(haetae5);

#undef KPQC_DECLARE_SIGNATURE
}

namespace kpqc::haetae {

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

KPQC_ACCESSOR(haetae2, "haetae-mode2", 992, 1408, 1474)
KPQC_ACCESSOR(haetae3, "haetae-mode3", 1472, 2112, 2349)
KPQC_ACCESSOR(haetae5, "haetae-mode5", 2080, 2752, 2948)

#undef KPQC_ACCESSOR

}  // namespace kpqc::haetae
