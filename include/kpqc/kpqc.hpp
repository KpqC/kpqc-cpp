#ifndef KPQC_KPQC_HPP
#define KPQC_KPQC_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace kpqc {

using Bytes = std::vector<std::uint8_t>;

namespace detail {

void secure_erase(void* data, std::size_t size) noexcept;

template <typename T>
class SecureAllocator {
public:
    using value_type = T;
    using is_always_equal = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        secure_erase(pointer, count * sizeof(T));
        std::allocator<T>{}.deallocate(pointer, count);
    }
};

template <typename T, typename U>
constexpr bool operator==(
    const SecureAllocator<T>&,
    const SecureAllocator<U>&) noexcept {
    return true;
}

template <typename T, typename U>
constexpr bool operator!=(
    const SecureAllocator<T>&,
    const SecureAllocator<U>&) noexcept {
    return false;
}

}  // namespace detail

using SecretBytes =
    std::vector<std::uint8_t, detail::SecureAllocator<std::uint8_t>>;

void secure_clear(Bytes& value) noexcept;
void secure_clear(SecretBytes& value) noexcept;

struct KeyPair {
    Bytes public_key;
    SecretBytes secret_key;
};

struct EncapsulatedSecret {
    Bytes ciphertext;
    SecretBytes shared_secret;
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

    [[nodiscard]] const std::string& operation() const noexcept;
    [[nodiscard]] int status() const noexcept;

private:
    std::string operation_;
    int status_;
};

namespace detail {
struct Registry;
}

class SignatureAlgorithm final {
public:
    [[nodiscard]] std::string_view id() const noexcept;
    [[nodiscard]] const SignatureSizes& sizes() const noexcept;

    [[nodiscard]] KeyPair generate_key_pair() const;
    [[nodiscard]] Bytes sign(
        const Bytes& message,
        const SecretBytes& secret_key,
        const Bytes& context = {}) const;
    [[nodiscard]] Bytes sign(
        const Bytes& message,
        const Bytes& secret_key,
        const Bytes& context = {}) const;
    [[nodiscard]] bool verify(
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

    Bytes sign_with_key(
        const Bytes& message,
        const std::uint8_t* secret_key,
        std::size_t secret_key_size,
        const Bytes& context) const;

    const char* id_;
    SignatureSizes sizes_;
    KeyPairFunction key_pair_;
    SignFunction sign_;
    VerifyFunction verify_;

    friend struct detail::Registry;
};

class KeyEncapsulationAlgorithm final {
public:
    [[nodiscard]] std::string_view id() const noexcept;
    [[nodiscard]] const KemSizes& sizes() const noexcept;

    [[nodiscard]] KeyPair generate_key_pair() const;
    [[nodiscard]] EncapsulatedSecret encapsulate(const Bytes& public_key) const;
    [[nodiscard]] SecretBytes decapsulate(
        const Bytes& ciphertext,
        const SecretBytes& secret_key) const;
    [[nodiscard]] SecretBytes decapsulate(
        const Bytes& ciphertext,
        const Bytes& secret_key) const;

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

    SecretBytes decapsulate_with_key(
        const Bytes& ciphertext,
        const std::uint8_t* secret_key,
        std::size_t secret_key_size) const;

    const char* id_;
    KemSizes sizes_;
    KeyPairFunction key_pair_;
    EncapsulateFunction encapsulate_;
    DecapsulateFunction decapsulate_;

    friend struct detail::Registry;
};

namespace aimer {
[[nodiscard]] const SignatureAlgorithm& aimer128f() noexcept;
[[nodiscard]] const SignatureAlgorithm& aimer128s() noexcept;
[[nodiscard]] const SignatureAlgorithm& aimer192f() noexcept;
[[nodiscard]] const SignatureAlgorithm& aimer192s() noexcept;
[[nodiscard]] const SignatureAlgorithm& aimer256f() noexcept;
[[nodiscard]] const SignatureAlgorithm& aimer256s() noexcept;
}

namespace haetae {
[[nodiscard]] const SignatureAlgorithm& haetae2() noexcept;
[[nodiscard]] const SignatureAlgorithm& haetae3() noexcept;
[[nodiscard]] const SignatureAlgorithm& haetae5() noexcept;
}

namespace ntruplus {
[[nodiscard]] const KeyEncapsulationAlgorithm& ntruplus768() noexcept;
[[nodiscard]] const KeyEncapsulationAlgorithm& ntruplus864() noexcept;
[[nodiscard]] const KeyEncapsulationAlgorithm& ntruplus1152() noexcept;
}

namespace smaugt {
[[nodiscard]] const KeyEncapsulationAlgorithm& smaugt128() noexcept;
[[nodiscard]] const KeyEncapsulationAlgorithm& smaugt192() noexcept;
[[nodiscard]] const KeyEncapsulationAlgorithm& smaugt256() noexcept;
[[nodiscard]] const KeyEncapsulationAlgorithm& timer() noexcept;
}

}  // namespace kpqc

#endif
