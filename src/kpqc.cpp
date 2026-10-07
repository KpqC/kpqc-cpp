#include "kpqc/kpqc.hpp"

#include <sstream>
#include <utility>

namespace kpqc {
namespace {

constexpr int allocation_failure = -2;
constexpr std::uint8_t empty_input = 0;

const std::uint8_t* input(const Bytes& value) noexcept {
    return value.empty() ? &empty_input : value.data();
}

void require_size(
    std::size_t actual,
    std::size_t expected,
    std::string_view label) {
    if (actual == expected) {
        return;
    }
    std::ostringstream message;
    message << label << " must be " << expected << " bytes, received "
            << actual;
    throw std::invalid_argument(message.str());
}

void require_context(const Bytes& context) {
    if (context.size() <= 255) {
        return;
    }
    std::ostringstream message;
    message << "context cannot exceed 255 bytes, received " << context.size();
    throw std::invalid_argument(message.str());
}

std::string error_message(const std::string& operation, int status) {
    std::ostringstream message;
    message << operation << " failed with status " << status;
    return message.str();
}

}  // namespace

namespace detail {

void secure_erase(void* data, std::size_t size) noexcept {
    volatile std::uint8_t* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size != 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace detail

void secure_clear(Bytes& value) noexcept {
    detail::secure_erase(value.data(), value.size());
    value.clear();
}

void secure_clear(SecretBytes& value) noexcept {
    detail::secure_erase(value.data(), value.size());
    value.clear();
}

Error::Error(std::string operation, int status)
    : std::runtime_error(error_message(operation, status)),
      operation_(std::move(operation)),
      status_(status) {}

const std::string& Error::operation() const noexcept {
    return operation_;
}

int Error::status() const noexcept {
    return status_;
}

SignatureAlgorithm::SignatureAlgorithm(
    const char* id,
    SignatureSizes sizes,
    KeyPairFunction key_pair,
    SignFunction sign,
    VerifyFunction verify) noexcept
    : id_(id),
      sizes_(sizes),
      key_pair_(key_pair),
      sign_(sign),
      verify_(verify) {}

std::string_view SignatureAlgorithm::id() const noexcept {
    return id_;
}

const SignatureSizes& SignatureAlgorithm::sizes() const noexcept {
    return sizes_;
}

KeyPair SignatureAlgorithm::generate_key_pair() const {
    KeyPair result{Bytes(sizes_.public_key), SecretBytes(sizes_.secret_key)};
    const int status =
        key_pair_(result.public_key.data(), result.secret_key.data());
    if (status != 0) {
        secure_clear(result.public_key);
        secure_clear(result.secret_key);
        throw Error("key generation", status);
    }
    return result;
}

Bytes SignatureAlgorithm::sign(
    const Bytes& message,
    const SecretBytes& secret_key,
    const Bytes& context) const {
    return sign_with_key(
        message, secret_key.data(), secret_key.size(), context);
}

Bytes SignatureAlgorithm::sign(
    const Bytes& message,
    const Bytes& secret_key,
    const Bytes& context) const {
    return sign_with_key(
        message, secret_key.data(), secret_key.size(), context);
}

Bytes SignatureAlgorithm::sign_with_key(
    const Bytes& message,
    const std::uint8_t* secret_key,
    std::size_t secret_key_size,
    const Bytes& context) const {
    require_size(secret_key_size, sizes_.secret_key, "secret_key");
    require_context(context);

    Bytes signature(sizes_.signature);
    std::size_t signature_length = 0;
    const int status = sign_(
        signature.data(), &signature_length, input(message), message.size(),
        input(context), context.size(), secret_key);
    if (status != 0 || signature_length != sizes_.signature) {
        secure_clear(signature);
        throw Error("signing", status != 0 ? status : -1);
    }
    return signature;
}

bool SignatureAlgorithm::verify(
    const Bytes& message,
    const Bytes& signature,
    const Bytes& public_key,
    const Bytes& context) const {
    require_size(public_key.size(), sizes_.public_key, "public_key");
    require_context(context);
    if (signature.size() != sizes_.signature) {
        return false;
    }
    const int status = verify_(
        signature.data(), signature.size(), input(message), message.size(),
        input(context), context.size(), public_key.data());
    if (status == allocation_failure) {
        throw Error("verification", status);
    }
    return status == 0;
}

KeyEncapsulationAlgorithm::KeyEncapsulationAlgorithm(
    const char* id,
    KemSizes sizes,
    KeyPairFunction key_pair,
    EncapsulateFunction encapsulate,
    DecapsulateFunction decapsulate) noexcept
    : id_(id),
      sizes_(sizes),
      key_pair_(key_pair),
      encapsulate_(encapsulate),
      decapsulate_(decapsulate) {}

std::string_view KeyEncapsulationAlgorithm::id() const noexcept {
    return id_;
}

const KemSizes& KeyEncapsulationAlgorithm::sizes() const noexcept {
    return sizes_;
}

KeyPair KeyEncapsulationAlgorithm::generate_key_pair() const {
    KeyPair result{Bytes(sizes_.public_key), SecretBytes(sizes_.secret_key)};
    const int status =
        key_pair_(result.public_key.data(), result.secret_key.data());
    if (status != 0) {
        secure_clear(result.public_key);
        secure_clear(result.secret_key);
        throw Error("key generation", status);
    }
    return result;
}

EncapsulatedSecret KeyEncapsulationAlgorithm::encapsulate(
    const Bytes& public_key) const {
    require_size(public_key.size(), sizes_.public_key, "public_key");
    EncapsulatedSecret result{
        Bytes(sizes_.ciphertext), SecretBytes(sizes_.shared_secret)};
    const int status = encapsulate_(
        result.ciphertext.data(), result.shared_secret.data(),
        public_key.data());
    if (status != 0) {
        secure_clear(result.ciphertext);
        secure_clear(result.shared_secret);
        throw Error("encapsulation", status);
    }
    return result;
}

SecretBytes KeyEncapsulationAlgorithm::decapsulate(
    const Bytes& ciphertext,
    const SecretBytes& secret_key) const {
    return decapsulate_with_key(
        ciphertext, secret_key.data(), secret_key.size());
}

SecretBytes KeyEncapsulationAlgorithm::decapsulate(
    const Bytes& ciphertext,
    const Bytes& secret_key) const {
    return decapsulate_with_key(
        ciphertext, secret_key.data(), secret_key.size());
}

SecretBytes KeyEncapsulationAlgorithm::decapsulate_with_key(
    const Bytes& ciphertext,
    const std::uint8_t* secret_key,
    std::size_t secret_key_size) const {
    require_size(ciphertext.size(), sizes_.ciphertext, "ciphertext");
    require_size(secret_key_size, sizes_.secret_key, "secret_key");
    SecretBytes shared_secret(sizes_.shared_secret);
    const int status = decapsulate_(
        shared_secret.data(), ciphertext.data(), secret_key);
    if (status != 0) {
        secure_clear(shared_secret);
        throw Error("decapsulation", status);
    }
    return shared_secret;
}

}  // namespace kpqc
