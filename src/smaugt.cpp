#include "registry.hpp"

#include <cstdint>

extern "C" {

#define KPQC_DECLARE_KEM(name)                                                \
    int kpqc_##name##_keypair(std::uint8_t*, std::uint8_t*);                 \
    int kpqc_##name##_encapsulate(                                            \
        std::uint8_t*, std::uint8_t*, const std::uint8_t*);                  \
    int kpqc_##name##_decapsulate(                                            \
        std::uint8_t*, const std::uint8_t*, const std::uint8_t*)

KPQC_DECLARE_KEM(smaugt128);
KPQC_DECLARE_KEM(smaugt192);
KPQC_DECLARE_KEM(smaugt256);
KPQC_DECLARE_KEM(timer);

#undef KPQC_DECLARE_KEM
}

namespace kpqc::smaugt {

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

KPQC_ACCESSOR(smaugt128, "SMAUG-T128", 672, 832, 672)
KPQC_ACCESSOR(smaugt192, "SMAUG-T192", 1088, 1312, 992)
KPQC_ACCESSOR(smaugt256, "SMAUG-T256", 1440, 1728, 1376)
KPQC_ACCESSOR(timer, "TiMER", 672, 832, 608)

#undef KPQC_ACCESSOR

}  // namespace kpqc::smaugt
