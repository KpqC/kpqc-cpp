#include "kpqc/kpqc.hpp"

#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

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

struct SignatureCase {
    const kpqc::SignatureAlgorithm* algorithm;
    std::string_view id;
    kpqc::SignatureSizes sizes;
};

struct KemCase {
    const kpqc::KeyEncapsulationAlgorithm* algorithm;
    std::string_view id;
    kpqc::KemSizes sizes;
    bool implicit_rejection;
};

void check_signature(const SignatureCase& test) {
    const kpqc::SignatureAlgorithm& algorithm = *test.algorithm;
    const kpqc::SignatureSizes& sizes = algorithm.sizes();
    require(algorithm.id() == test.id, std::string(test.id) + " identifier");
    require(sizes.public_key == test.sizes.public_key,
            std::string(test.id) + " declared public-key size");
    require(sizes.secret_key == test.sizes.secret_key,
            std::string(test.id) + " declared secret-key size");
    require(sizes.signature == test.sizes.signature,
            std::string(test.id) + " declared signature size");

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
    const kpqc::KemSizes& sizes = algorithm.sizes();
    require(algorithm.id() == test.id, std::string(test.id) + " identifier");
    require(sizes.public_key == test.sizes.public_key,
            std::string(test.id) + " declared public-key size");
    require(sizes.secret_key == test.sizes.secret_key,
            std::string(test.id) + " declared secret-key size");
    require(sizes.ciphertext == test.sizes.ciphertext,
            std::string(test.id) + " declared ciphertext size");
    require(sizes.shared_secret == test.sizes.shared_secret,
            std::string(test.id) + " declared shared-secret size");

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
        const kpqc::SecretBytes replacement =
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
        const std::array<SignatureCase, 9> signatures{{
            {&kpqc::aimer::aimer128f(), "aimer-128f", {32, 48, 6944}},
            {&kpqc::aimer::aimer128s(), "aimer-128s", {32, 48, 4704}},
            {&kpqc::aimer::aimer192f(), "aimer-192f", {48, 72, 15408}},
            {&kpqc::aimer::aimer192s(), "aimer-192s", {48, 72, 10320}},
            {&kpqc::aimer::aimer256f(), "aimer-256f", {64, 96, 31360}},
            {&kpqc::aimer::aimer256s(), "aimer-256s", {64, 96, 20224}},
            {&kpqc::haetae::haetae2(), "haetae-mode2", {992, 1408, 1474}},
            {&kpqc::haetae::haetae3(), "haetae-mode3", {1472, 2112, 2349}},
            {&kpqc::haetae::haetae5(), "haetae-mode5", {2080, 2752, 2948}},
        }};
        const std::array<KemCase, 7> kems{{
            {&kpqc::ntruplus::ntruplus768(),
             "NTRU+768", {1152, 2336, 1152, 32}, false},
            {&kpqc::ntruplus::ntruplus864(),
             "NTRU+864", {1296, 2624, 1296, 32}, false},
            {&kpqc::ntruplus::ntruplus1152(),
             "NTRU+1152", {1728, 3488, 1728, 32}, false},
            {&kpqc::smaugt::smaugt128(),
             "SMAUG-T128", {672, 832, 672, 32}, true},
            {&kpqc::smaugt::smaugt192(),
             "SMAUG-T192", {1088, 1312, 992, 32}, true},
            {&kpqc::smaugt::smaugt256(),
             "SMAUG-T256", {1440, 1728, 1376, 32}, true},
            {&kpqc::smaugt::timer(),
             "TiMER", {672, 832, 608, 32}, true},
        }};

        for (const SignatureCase& test : signatures) {
            check_signature(test);
        }
        for (const KemCase& test : kems) {
            check_kem(test);
        }

        const kpqc::SignatureAlgorithm& signature =
            kpqc::aimer::aimer128f();
        const kpqc::KeyPair signature_keys = signature.generate_key_pair();
        expect_invalid_argument(
            [&signature] {
                static_cast<void>(signature.sign({}, kpqc::Bytes{0}));
            },
            "short secret key");
        expect_invalid_argument(
            [&signature, &signature_keys] {
                static_cast<void>(signature.sign(
                    {}, signature_keys.secret_key, kpqc::Bytes(256)));
            },
            "long signature context");

        const kpqc::KeyEncapsulationAlgorithm& kem =
            kpqc::ntruplus::ntruplus768();
        expect_invalid_argument(
            [&kem] { static_cast<void>(kem.encapsulate({0})); },
            "short public key");

        kpqc::SecretBytes secret{1, 2, 3, 4};
        kpqc::secure_clear(secret);
        require(secret.empty(), "explicit secret clearing");

        kpqc::Bytes bytes{1, 2, 3, 4};
        kpqc::secure_clear(bytes);
        require(bytes.empty(), "explicit byte clearing");

        std::cout << "C++ API behavior checks passed across 16 parameter sets.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "API failure: " << error.what() << '\n';
        return 1;
    }
}
