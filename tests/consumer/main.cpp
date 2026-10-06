#include <kpqc/kpqc.hpp>

int main() {
    const auto& algorithm = kpqc::aimer::aimer128f();
    const kpqc::KeyPair keys = algorithm.generate_key_pair();
    const kpqc::Bytes message{'K', 'p', 'q', 'C'};
    const kpqc::Bytes signature = algorithm.sign(message, keys.secret_key);
    return algorithm.verify(message, signature, keys.public_key) ? 0 : 1;
}
