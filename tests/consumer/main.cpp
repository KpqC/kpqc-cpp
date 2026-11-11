#include <kpqc/kpqc.hpp>

namespace {

bool check_signature(const kpqc::SignatureAlgorithm& algorithm) {
    const kpqc::Bytes message{'K', 'p', 'q', 'C'};
    const kpqc::KeyPair keys = algorithm.generate_key_pair();
    const kpqc::Bytes signature = algorithm.sign(message, keys.secret_key);
    return algorithm.verify(message, signature, keys.public_key);
}

bool check_kem(const kpqc::KeyEncapsulationAlgorithm& algorithm) {
    const kpqc::KeyPair keys = algorithm.generate_key_pair();
    const kpqc::EncapsulatedSecret outbound =
        algorithm.encapsulate(keys.public_key);
    return algorithm.decapsulate(outbound.ciphertext, keys.secret_key) ==
           outbound.shared_secret;
}

}  // namespace

int main() {
    const bool signatures =
        check_signature(kpqc::aimer::aimer128f()) &&
        check_signature(kpqc::haetae::haetae2());
    const bool kems =
        check_kem(kpqc::ntruplus::ntruplus768()) &&
        check_kem(kpqc::smaugt::smaugt128());
    return signatures && kems ? 0 : 1;
}
