#include "kpqc/kpqc.hpp"

#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& label) {
    if (!condition) {
        throw std::runtime_error(label + " failed");
    }
}

void expect_invalid_argument(
    const std::function<void()>& action,
    const std::string& label) {
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(label + " did not reject invalid input");
}

void expect_native_error(
    const std::function<void()>& action,
    const std::string& label) {
    try {
        action();
    } catch (const kpqc::Error&) {
        return;
    }
    throw std::runtime_error(label + " did not report a native failure");
}

struct KemCase {
    const kpqc::KeyEncapsulationAlgorithm* algorithm;
    bool implicit_rejection;
};

void check_signature(const kpqc::SignatureAlgorithm& algorithm) {
    const kpqc::KeyPair keys = algorithm.generate_key_pair();
    require(keys.public_key.size() == algorithm.sizes().public_key,
            std::string(algorithm.id()) + " public-key size");
    require(keys.secret_key.size() == algorithm.sizes().secret_key,
            std::string(algorithm.id()) + " secret-key size");

    const kpqc::Bytes message{'K', 'p', 'q', 'C', ' ', 'C', '+', '+'};
    const kpqc::Bytes context{'r', 'e', 'l', 'e', 'a', 's', 'e'};
    const kpqc::Bytes signature = algorithm.sign(message, keys.secret_key, context);
    require(signature.size() == algorithm.sizes().signature,
            std::string(algorithm.id()) + " signature size");
    require(algorithm.verify(message, signature, keys.public_key, context),
            std::string(algorithm.id()) + " verification");

    kpqc::Bytes altered_signature = signature;
    altered_signature.front() ^= 1U;
    require(!algorithm.verify(message, altered_signature, keys.public_key, context),
            std::string(algorithm.id()) + " altered-signature rejection");
    require(!algorithm.verify(message, kpqc::Bytes{0}, keys.public_key, context),
            std::string(algorithm.id()) + " short-signature rejection");
    require(!algorithm.verify(message, signature, keys.public_key, {'x'}),
            std::string(algorithm.id()) + " wrong-context rejection");
}

void check_kem(const KemCase& test) {
    const kpqc::KeyEncapsulationAlgorithm& algorithm = *test.algorithm;
    const kpqc::KeyPair keys = algorithm.generate_key_pair();
    require(keys.public_key.size() == algorithm.sizes().public_key,
            std::string(algorithm.id()) + " public-key size");
    require(keys.secret_key.size() == algorithm.sizes().secret_key,
            std::string(algorithm.id()) + " secret-key size");
    const kpqc::EncapsulatedSecret outbound =
        algorithm.encapsulate(keys.public_key);
    require(outbound.ciphertext.size() == algorithm.sizes().ciphertext,
            std::string(algorithm.id()) + " ciphertext size");
    require(outbound.shared_secret.size() == algorithm.sizes().shared_secret,
            std::string(algorithm.id()) + " shared-secret size");
    require(algorithm.decapsulate(outbound.ciphertext, keys.secret_key) ==
                outbound.shared_secret,
            std::string(algorithm.id()) + " decapsulation");

    kpqc::Bytes altered_ciphertext = outbound.ciphertext;
    altered_ciphertext.front() ^= 1U;
    if (test.implicit_rejection) {
        const kpqc::Bytes replacement =
            algorithm.decapsulate(altered_ciphertext, keys.secret_key);
        require(replacement != outbound.shared_secret,
                std::string(algorithm.id()) + " implicit rejection");
    } else {
        expect_native_error(
            [&algorithm, &altered_ciphertext, &keys] {
                static_cast<void>(algorithm.decapsulate(
                    altered_ciphertext, keys.secret_key));
            },
            std::string(algorithm.id()) + " altered-ciphertext rejection");
        expect_native_error(
            [&algorithm] {
                static_cast<void>(algorithm.encapsulate(
                    kpqc::Bytes(algorithm.sizes().public_key, 0xff)));
            },
            std::string(algorithm.id()) + " non-canonical public-key rejection");
    }

    expect_invalid_argument(
        [&algorithm, &keys] {
            static_cast<void>(algorithm.decapsulate(
                kpqc::Bytes(algorithm.sizes().ciphertext - 1),
                keys.secret_key));
        },
        std::string(algorithm.id()) + " short ciphertext");
    expect_invalid_argument(
        [&algorithm, &outbound] {
            static_cast<void>(algorithm.decapsulate(
                outbound.ciphertext,
                kpqc::Bytes(algorithm.sizes().secret_key - 1)));
        },
        std::string(algorithm.id()) + " short secret key");
}

}  // namespace

int main() {
    try {
        const std::array<const kpqc::SignatureAlgorithm*, 9> signatures{{
            &kpqc::aimer::aimer128f(), &kpqc::aimer::aimer128s(),
            &kpqc::aimer::aimer192f(), &kpqc::aimer::aimer192s(),
            &kpqc::aimer::aimer256f(), &kpqc::aimer::aimer256s(),
            &kpqc::haetae::haetae2(), &kpqc::haetae::haetae3(),
            &kpqc::haetae::haetae5(),
        }};
        const std::array<KemCase, 7> kems{{
            {&kpqc::ntruplus::ntruplus768(), false},
            {&kpqc::ntruplus::ntruplus864(), false},
            {&kpqc::ntruplus::ntruplus1152(), false},
            {&kpqc::smaugt::smaugt128(), true},
            {&kpqc::smaugt::smaugt192(), true},
            {&kpqc::smaugt::smaugt256(), true},
            {&kpqc::smaugt::timer(), true},
        }};

        for (const kpqc::SignatureAlgorithm* algorithm : signatures) {
            check_signature(*algorithm);
        }
        for (const KemCase& test : kems) {
            check_kem(test);
        }

        const kpqc::SignatureAlgorithm& signature =
            kpqc::aimer::aimer128f();
        const kpqc::KeyPair signature_keys = signature.generate_key_pair();
        expect_invalid_argument(
            [&signature] { signature.sign({}, {0}); }, "short secret key");
        expect_invalid_argument(
            [&signature, &signature_keys] {
                signature.sign({}, signature_keys.secret_key, kpqc::Bytes(256));
            },
            "long signature context");

        const kpqc::KeyEncapsulationAlgorithm& kem =
            kpqc::ntruplus::ntruplus768();
        expect_invalid_argument(
            [&kem] { kem.encapsulate({0}); }, "short public key");

        std::cout << "C++ API behavior checks passed across 16 parameter sets.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "API failure: " << error.what() << '\n';
        return 1;
    }
}
