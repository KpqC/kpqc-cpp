#include "registry.hpp"

#include <cstdint>

extern "C" {

#define KPQC_DECLARE_KEM(name)                                                \
    int kpqc_##name##_keypair(std::uint8_t*, std::uint8_t*);                 \
    int kpqc_##name##_encapsulate(                                            \
        std::uint8_t*, std::uint8_t*, const std::uint8_t*);                  \
    int kpqc_##name##_decapsulate(                                            \
        std::uint8_t*, const std::uint8_t*, const std::uint8_t*)

KPQC_DECLARE_KEM(ntruplus768);
KPQC_DECLARE_KEM(ntruplus864);
KPQC_DECLARE_KEM(ntruplus1152);

#undef KPQC_DECLARE_KEM
}

namespace kpqc::ntruplus {

#define KPQC_ACCESSOR(accessor, algorithm_id, public_key_size,                \
                      secret_key_size, ciphertext_size)                       \
    const KeyEncapsulationAlgorithm& accessor() noexcept {                    \
        static const KeyEncapsulationAlgorithm value = detail::Registry::kem( \
            algorithm_id,                                                     \
            {public_key_size, secret_key_size, ciphertext_size, 32},          \
            kpqc_##accessor##_keypair,                                        \
            kpqc_##accessor##_encapsulate,                                    \
            kpqc_##accessor##_decapsulate);                                   \
        return value;                                                         \
    }

KPQC_ACCESSOR(ntruplus768, "NTRU+768", 1152, 2336, 1152)
KPQC_ACCESSOR(ntruplus864, "NTRU+864", 1296, 2624, 1296)
KPQC_ACCESSOR(ntruplus1152, "NTRU+1152", 1728, 3488, 1728)

#undef KPQC_ACCESSOR

}  // namespace kpqc::ntruplus
