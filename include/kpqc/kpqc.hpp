#ifndef KPQC_KPQC_HPP
#define KPQC_KPQC_HPP

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kpqc {

using Bytes = std::vector<std::uint8_t>;

struct KeyPair {
    Bytes public_key;
    Bytes secret_key;
};

struct EncapsulatedSecret {
    Bytes ciphertext;
    Bytes shared_secret;
};

struct SignatureSizes {
    std::size_t public_key;
    std::size_t secret_key;
    std::size_t signature;
};

struct KemSizes {
    std::size_t public_key;
    std::size_t secret_key;
    std::size_t ciphertext;
    std::size_t shared_secret;
};

class Error final : public std::runtime_error {
public:
    Error(std::string operation, int status);

    const std::string& operation() const noexcept;
    int status() const noexcept;

private:
    std::string operation_;
    int status_;
};

namespace detail {
struct Registry;
}

class SignatureAlgorithm final {
public:
    std::string_view id() const noexcept;
    const SignatureSizes& sizes() const noexcept;

    KeyPair generate_key_pair() const;
    Bytes sign(
        const Bytes& message,
        const Bytes& secret_key,
        const Bytes& context = {}) const;
    bool verify(
        const Bytes& message,
        const Bytes& signature,
        const Bytes& public_key,
        const Bytes& context = {}) const;

private:
    using KeyPairFunction = int (*)(std::uint8_t*, std::uint8_t*);
    using SignFunction = int (*)(
        std::uint8_t*, std::size_t*, const std::uint8_t*, std::size_t,
        const std::uint8_t*, std::size_t, const std::uint8_t*);
    using VerifyFunction = int (*)(
        const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
        const std::uint8_t*, std::size_t, const std::uint8_t*);

    SignatureAlgorithm(
        const char* id,
        SignatureSizes sizes,
        KeyPairFunction key_pair,
        SignFunction sign,
        VerifyFunction verify) noexcept;

    const char* id_;
    SignatureSizes sizes_;
    KeyPairFunction key_pair_;
    SignFunction sign_;
    VerifyFunction verify_;

    friend struct detail::Registry;
};

class KeyEncapsulationAlgorithm final {
public:
    std::string_view id() const noexcept;
    const KemSizes& sizes() const noexcept;

    KeyPair generate_key_pair() const;
    EncapsulatedSecret encapsulate(const Bytes& public_key) const;
    Bytes decapsulate(const Bytes& ciphertext, const Bytes& secret_key) const;

private:
    using KeyPairFunction = int (*)(std::uint8_t*, std::uint8_t*);
    using EncapsulateFunction = int (*)(
        std::uint8_t*, std::uint8_t*, const std::uint8_t*);
    using DecapsulateFunction = int (*)(
        std::uint8_t*, const std::uint8_t*, const std::uint8_t*);

    KeyEncapsulationAlgorithm(
        const char* id,
        KemSizes sizes,
        KeyPairFunction key_pair,
        EncapsulateFunction encapsulate,
        DecapsulateFunction decapsulate) noexcept;

    const char* id_;
    KemSizes sizes_;
    KeyPairFunction key_pair_;
    EncapsulateFunction encapsulate_;
    DecapsulateFunction decapsulate_;

    friend struct detail::Registry;
};

namespace aimer {
const SignatureAlgorithm& aimer128f() noexcept;
const SignatureAlgorithm& aimer128s() noexcept;
const SignatureAlgorithm& aimer192f() noexcept;
const SignatureAlgorithm& aimer192s() noexcept;
const SignatureAlgorithm& aimer256f() noexcept;
const SignatureAlgorithm& aimer256s() noexcept;
}

namespace haetae {
const SignatureAlgorithm& haetae2() noexcept;
const SignatureAlgorithm& haetae3() noexcept;
const SignatureAlgorithm& haetae5() noexcept;
}

namespace ntruplus {
const KeyEncapsulationAlgorithm& ntruplus768() noexcept;
const KeyEncapsulationAlgorithm& ntruplus864() noexcept;
const KeyEncapsulationAlgorithm& ntruplus1152() noexcept;
}

namespace smaugt {
const KeyEncapsulationAlgorithm& smaugt128() noexcept;
const KeyEncapsulationAlgorithm& smaugt192() noexcept;
const KeyEncapsulationAlgorithm& smaugt256() noexcept;
const KeyEncapsulationAlgorithm& timer() noexcept;
}

}  // namespace kpqc

#endif
