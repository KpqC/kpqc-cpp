#ifndef KPQC_SRC_REGISTRY_HPP
#define KPQC_SRC_REGISTRY_HPP

#include "kpqc/kpqc.hpp"

#include <cstddef>
#include <cstdint>

namespace kpqc::detail {

struct Registry {
    static SignatureAlgorithm signature(
        const char* id,
        SignatureSizes sizes,
        SignatureAlgorithm::KeyPairFunction key_pair,
        SignatureAlgorithm::SignFunction sign,
        SignatureAlgorithm::VerifyFunction verify) noexcept {
        return SignatureAlgorithm(id, sizes, key_pair, sign, verify);
    }

    static KeyEncapsulationAlgorithm kem(
        const char* id,
        KemSizes sizes,
        KeyEncapsulationAlgorithm::KeyPairFunction key_pair,
        KeyEncapsulationAlgorithm::EncapsulateFunction encapsulate,
        KeyEncapsulationAlgorithm::DecapsulateFunction decapsulate) noexcept {
        return KeyEncapsulationAlgorithm(
            id, sizes, key_pair, encapsulate, decapsulate);
    }
};

}  // namespace kpqc::detail

#define KPQC_DECLARE_SIGNATURE(name)                                          \
    int kpqc_##name##_keypair(std::uint8_t*, std::uint8_t*);                 \
    int kpqc_##name##_sign(                                                   \
        std::uint8_t*, std::size_t*, const std::uint8_t*, std::size_t,        \
        const std::uint8_t*, std::size_t, const std::uint8_t*);               \
    int kpqc_##name##_verify(                                                 \
        const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,   \
        const std::uint8_t*, std::size_t, const std::uint8_t*)

#define KPQC_DEFINE_SIGNATURE(accessor, algorithm_id, public_key_size,        \
                              secret_key_size, signature_size)                \
    const SignatureAlgorithm& accessor() noexcept {                           \
        static const SignatureAlgorithm algorithm =                          \
            detail::Registry::signature(                                     \
                algorithm_id,                                                \
                {public_key_size, secret_key_size, signature_size},          \
                kpqc_##accessor##_keypair, kpqc_##accessor##_sign,            \
                kpqc_##accessor##_verify);                                   \
        return algorithm;                                                     \
    }

#define KPQC_DECLARE_KEM(name)                                                \
    int kpqc_##name##_keypair(std::uint8_t*, std::uint8_t*);                 \
    int kpqc_##name##_encapsulate(                                            \
        std::uint8_t*, std::uint8_t*, const std::uint8_t*);                  \
    int kpqc_##name##_decapsulate(                                            \
        std::uint8_t*, const std::uint8_t*, const std::uint8_t*)

#define KPQC_DEFINE_KEM(accessor, algorithm_id, public_key_size,              \
                        secret_key_size, ciphertext_size,                    \
                        shared_secret_size)                                  \
    const KeyEncapsulationAlgorithm& accessor() noexcept {                    \
        static const KeyEncapsulationAlgorithm algorithm =                   \
            detail::Registry::kem(                                           \
                algorithm_id,                                                \
                {public_key_size, secret_key_size, ciphertext_size,          \
                 shared_secret_size},                                        \
                kpqc_##accessor##_keypair, kpqc_##accessor##_encapsulate,     \
                kpqc_##accessor##_decapsulate);                              \
        return algorithm;                                                     \
    }

#endif
