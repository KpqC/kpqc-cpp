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

void clear(Bytes& value) noexcept {
    volatile std::uint8_t* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index) {
        cursor[index] = 0;
    }
}

void require_size(
    const Bytes& value,
    std::size_t expected,
    std::string_view label) {
    if (value.size() == expected) {
        return;
    }
    std::ostringstream message;
    message << label << " must be " << expected << " bytes, received "
            << value.size();
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
    KeyPair result{Bytes(sizes_.public_key), Bytes(sizes_.secret_key)};
    const int status = key_pair_(result.public_key.data(), result.secret_key.data());
    if (status != 0) {
        clear(result.public_key);
        clear(result.secret_key);
        throw Error("key generation", status);
    }
    return result;
}

Bytes SignatureAlgorithm::sign(
    const Bytes& message,
    const Bytes& secret_key,
    const Bytes& context) const {
    require_size(secret_key, sizes_.secret_key, "secret_key");
    require_context(context);

    Bytes signature(sizes_.signature);
    std::size_t signature_length = 0;
    const int status = sign_(
        signature.data(), &signature_length, input(message), message.size(),
        input(context), context.size(), secret_key.data());
    if (status != 0 || signature_length != sizes_.signature) {
        clear(signature);
        throw Error("signing", status != 0 ? status : -1);
    }
    return signature;
}

bool SignatureAlgorithm::verify(
    const Bytes& message,
    const Bytes& signature,
    const Bytes& public_key,
    const Bytes& context) const {
    require_size(public_key, sizes_.public_key, "public_key");
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
    KeyPair result{Bytes(sizes_.public_key), Bytes(sizes_.secret_key)};
    const int status = key_pair_(result.public_key.data(), result.secret_key.data());
    if (status != 0) {
        clear(result.public_key);
        clear(result.secret_key);
        throw Error("key generation", status);
    }
    return result;
}

EncapsulatedSecret KeyEncapsulationAlgorithm::encapsulate(
    const Bytes& public_key) const {
    require_size(public_key, sizes_.public_key, "public_key");
    EncapsulatedSecret result{
        Bytes(sizes_.ciphertext), Bytes(sizes_.shared_secret)};
    const int status = encapsulate_(
        result.ciphertext.data(), result.shared_secret.data(), public_key.data());
    if (status != 0) {
        clear(result.ciphertext);
        clear(result.shared_secret);
        throw Error("encapsulation", status);
    }
    return result;
}

Bytes KeyEncapsulationAlgorithm::decapsulate(
    const Bytes& ciphertext,
    const Bytes& secret_key) const {
    require_size(ciphertext, sizes_.ciphertext, "ciphertext");
    require_size(secret_key, sizes_.secret_key, "secret_key");
    Bytes shared_secret(sizes_.shared_secret);
    const int status = decapsulate_(
        shared_secret.data(), ciphertext.data(), secret_key.data());
    if (status != 0) {
        clear(shared_secret);
        throw Error("decapsulation", status);
    }
    return shared_secret;
}

}  // namespace kpqc
