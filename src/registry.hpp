#ifndef KPQC_SRC_REGISTRY_HPP
#define KPQC_SRC_REGISTRY_HPP

#include "kpqc/kpqc.hpp"

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

#endif
