#include "kat_drbg.hpp"
#include "kpqc/kpqc.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace {

using EntropyCallback = int (*)(std::uint8_t*, std::size_t);
using EntropySetter = void (*)(EntropyCallback);

extern "C" {
#define KPQC_DECLARE_SETTER(name) \
    void kpqc_##name##_set_randombytes(EntropyCallback)
KPQC_DECLARE_SETTER(aimer128f);
KPQC_DECLARE_SETTER(aimer128s);
KPQC_DECLARE_SETTER(aimer192f);
KPQC_DECLARE_SETTER(aimer192s);
KPQC_DECLARE_SETTER(aimer256f);
KPQC_DECLARE_SETTER(aimer256s);
KPQC_DECLARE_SETTER(haetae2);
KPQC_DECLARE_SETTER(haetae3);
KPQC_DECLARE_SETTER(haetae5);
KPQC_DECLARE_SETTER(ntruplus768);
KPQC_DECLARE_SETTER(ntruplus864);
KPQC_DECLARE_SETTER(ntruplus1152);
KPQC_DECLARE_SETTER(smaugt128);
KPQC_DECLARE_SETTER(smaugt192);
KPQC_DECLARE_SETTER(smaugt256);
KPQC_DECLARE_SETTER(timer);
#undef KPQC_DECLARE_SETTER
}

using Vector = std::unordered_map<std::string, std::string>;

struct SignatureCase {
    const kpqc::SignatureAlgorithm* algorithm;
    const char* path;
    EntropySetter set_entropy;
    bool uses_kat_context;
};

struct KemCase {
    const kpqc::KeyEncapsulationAlgorithm* algorithm;
    const char* path;
    EntropySetter set_entropy;
};

thread_local kpqc::test::CtrDrbg* active_drbg = nullptr;

int provide_entropy(std::uint8_t* output, std::size_t length) noexcept {
    if (active_drbg == nullptr || (output == nullptr && length != 0)) {
        return -1;
    }
    try {
        const kpqc::Bytes generated = active_drbg->generate(length);
        std::copy(generated.begin(), generated.end(), output);
        return 0;
    } catch (...) {
        return -1;
    }
}

void require(bool condition, const std::string& label) {
    if (!condition) {
        throw std::runtime_error(label + " failed");
    }
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

unsigned hex_digit(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<unsigned>(value - '0');
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<unsigned>(value - 'A') + 10U;
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<unsigned>(value - 'a') + 10U;
    }
    throw std::runtime_error("invalid hexadecimal digit");
}

kpqc::Bytes decode_hex(const std::string& value) {
    if (value.size() % 2 != 0) {
        throw std::runtime_error("hexadecimal field has odd length");
    }
    kpqc::Bytes result(value.size() / 2);
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(
            (hex_digit(value[index * 2]) << 4U) |
            hex_digit(value[index * 2 + 1]));
    }
    return result;
}

const std::string& field(const Vector& vector, const std::string& name) {
    const auto found = vector.find(name);
    if (found == vector.end()) {
        throw std::runtime_error("missing vector field: " + name);
    }
    return found->second;
}

kpqc::Bytes binary(const Vector& vector, const std::string& name) {
    return decode_hex(field(vector, name));
}

std::filesystem::path vector_directory() {
    const char* configured = std::getenv("KPQC_TEST_VECTORS");
    if (configured != nullptr && configured[0] != '\0') {
        return configured;
    }
    return KPQC_DEFAULT_VECTOR_DIR;
}

std::size_t read_vectors(
    const std::filesystem::path& relative_path,
    const std::function<void(const Vector&)>& consume) {
    const std::filesystem::path path =
        vector_directory() / relative_path / "kat.rsp";
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("missing KAT file: " + path.string());
    }

    std::size_t count = 0;
    Vector vector;
    std::string line;
    while (std::getline(input, line)) {
        const std::size_t separator = line.find(" = ");
        if (separator == std::string::npos) {
            continue;
        }
        const std::string name = line.substr(0, separator);
        const std::string value = line.substr(separator + 3);
        if (name == "count" && !vector.empty()) {
            consume(vector);
            ++count;
            vector.clear();
        }
        vector.emplace(name, value);
    }
    if (!vector.empty()) {
        consume(vector);
        ++count;
    }
    return count;
}

void check_signature(const SignatureCase& test, const Vector& vector) {
    const std::string label = std::string(test.algorithm->id()) +
        " count=" + field(vector, "count");
    kpqc::test::CtrDrbg random(binary(vector, "seed"));
    active_drbg = &random;
    test.set_entropy(provide_entropy);

    const kpqc::KeyPair keys = test.algorithm->generate_key_pair();
    require(keys.public_key == binary(vector, "pk"), label + " public key");
    require(keys.secret_key == binary(vector, "sk"), label + " secret key");

    kpqc::Bytes context;
    if (test.uses_kat_context) {
        kpqc::test::CtrDrbg preview = random;
        static_cast<void>(preview.generate(32));
        const kpqc::Bytes encoded_length = preview.generate(1);
        context = preview.generate(encoded_length.front());
    }

    const kpqc::Bytes message = binary(vector, "msg");
    const kpqc::Bytes signature =
        test.algorithm->sign(message, keys.secret_key, context);
    kpqc::Bytes expected;
    if (vector.find("sig") != vector.end()) {
        expected = binary(vector, "sig");
    } else {
        const kpqc::Bytes signed_message = binary(vector, "sm");
        require(signed_message.size() >= message.size(), label + " signed message");
        expected.assign(
            signed_message.begin() + static_cast<std::ptrdiff_t>(message.size()),
            signed_message.end());
    }
    require(signature == expected, label + " signature");
    require(test.algorithm->verify(
                message, signature, keys.public_key, context),
            label + " verification");
}

void check_kem(const KemCase& test, const Vector& vector) {
    const std::string label = std::string(test.algorithm->id()) +
        " count=" + field(vector, "count");
    kpqc::test::CtrDrbg random(binary(vector, "seed"));
    active_drbg = &random;
    test.set_entropy(provide_entropy);

    const kpqc::KeyPair keys = test.algorithm->generate_key_pair();
    require(keys.public_key == binary(vector, "pk"), label + " public key");
    require(keys.secret_key == binary(vector, "sk"), label + " secret key");
    const kpqc::EncapsulatedSecret result =
        test.algorithm->encapsulate(keys.public_key);
    require(result.ciphertext == binary(vector, "ct"), label + " ciphertext");
    require(result.shared_secret == binary(vector, "ss"),
            label + " shared secret");
    require(test.algorithm->decapsulate(result.ciphertext, keys.secret_key) ==
                result.shared_secret,
            label + " decapsulation");
}

void check_signature_entropy_failure(const SignatureCase& test) {
    active_drbg = nullptr;
    test.set_entropy(provide_entropy);
    expect_native_error(
        [&test] {
            static_cast<void>(test.algorithm->generate_key_pair());
        },
        std::string(test.algorithm->id()) + " key-generation entropy failure");

    if (!test.uses_kat_context) {
        return;
    }

    kpqc::test::CtrDrbg random(kpqc::Bytes(48, 0x42));
    active_drbg = &random;
    const kpqc::KeyPair keys = test.algorithm->generate_key_pair();
    active_drbg = nullptr;
    expect_native_error(
        [&test, &keys] {
            static_cast<void>(test.algorithm->sign({}, keys.secret_key));
        },
        std::string(test.algorithm->id()) + " signing entropy failure");
}

void check_kem_entropy_failure(const KemCase& test) {
    kpqc::test::CtrDrbg random(kpqc::Bytes(48, 0x42));
    active_drbg = &random;
    test.set_entropy(provide_entropy);
    const kpqc::KeyPair keys = test.algorithm->generate_key_pair();

    active_drbg = nullptr;
    expect_native_error(
        [&test] {
            static_cast<void>(test.algorithm->generate_key_pair());
        },
        std::string(test.algorithm->id()) + " key-generation entropy failure");
    expect_native_error(
        [&test, &keys] {
            static_cast<void>(test.algorithm->encapsulate(keys.public_key));
        },
        std::string(test.algorithm->id()) + " encapsulation entropy failure");
}

void check_aes() {
    const kpqc::Bytes key_bytes = decode_hex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f");
    const kpqc::Bytes block_bytes =
        decode_hex("00112233445566778899aabbccddeeff");
    const kpqc::Bytes expected =
        decode_hex("8ea2b7ca516745bfeafc49904b496089");
    kpqc::test::AesKey key{};
    kpqc::test::AesBlock block{};
    std::copy(key_bytes.begin(), key_bytes.end(), key.begin());
    std::copy(block_bytes.begin(), block_bytes.end(), block.begin());
    const kpqc::test::AesBlock actual = kpqc::test::aes256_encrypt(key, block);
    require(std::equal(actual.begin(), actual.end(), expected.begin()),
            "AES-256 helper");
}

}  // namespace

int main() {
    try {
        check_aes();
        const std::array<SignatureCase, 9> signatures{{
            {&kpqc::aimer::aimer128f(), "aimer/128f", kpqc_aimer128f_set_randombytes, false},
            {&kpqc::aimer::aimer128s(), "aimer/128s", kpqc_aimer128s_set_randombytes, false},
            {&kpqc::aimer::aimer192f(), "aimer/192f", kpqc_aimer192f_set_randombytes, false},
            {&kpqc::aimer::aimer192s(), "aimer/192s", kpqc_aimer192s_set_randombytes, false},
            {&kpqc::aimer::aimer256f(), "aimer/256f", kpqc_aimer256f_set_randombytes, false},
            {&kpqc::aimer::aimer256s(), "aimer/256s", kpqc_aimer256s_set_randombytes, false},
            {&kpqc::haetae::haetae2(), "haetae/mode2", kpqc_haetae2_set_randombytes, true},
            {&kpqc::haetae::haetae3(), "haetae/mode3", kpqc_haetae3_set_randombytes, true},
            {&kpqc::haetae::haetae5(), "haetae/mode5", kpqc_haetae5_set_randombytes, true},
        }};
        const std::array<KemCase, 7> kems{{
            {&kpqc::ntruplus::ntruplus768(), "ntruplus/768", kpqc_ntruplus768_set_randombytes},
            {&kpqc::ntruplus::ntruplus864(), "ntruplus/864", kpqc_ntruplus864_set_randombytes},
            {&kpqc::ntruplus::ntruplus1152(), "ntruplus/1152", kpqc_ntruplus1152_set_randombytes},
            {&kpqc::smaugt::smaugt128(), "smaugt/mode1", kpqc_smaugt128_set_randombytes},
            {&kpqc::smaugt::smaugt192(), "smaugt/mode3", kpqc_smaugt192_set_randombytes},
            {&kpqc::smaugt::smaugt256(), "smaugt/mode5", kpqc_smaugt256_set_randombytes},
            {&kpqc::smaugt::timer(), "smaugt/modet", kpqc_timer_set_randombytes},
        }};

        std::size_t total = 0;
        for (const SignatureCase& test : signatures) {
            const std::size_t count = read_vectors(
                test.path, [&test](const Vector& vector) {
                    check_signature(test, vector);
                });
            require(count == 100, std::string(test.algorithm->id()) +
                                      " vector count");
            total += count;
            std::cout << test.algorithm->id() << ": " << count
                      << " KAT records passed\n";
        }
        for (const KemCase& test : kems) {
            const std::size_t count = read_vectors(
                test.path, [&test](const Vector& vector) {
                    check_kem(test, vector);
                });
            require(count == 100, std::string(test.algorithm->id()) +
                                      " vector count");
            total += count;
            std::cout << test.algorithm->id() << ": " << count
                      << " KAT records passed\n";
        }
        require(total == 1600, "total vector count");

        for (const SignatureCase& test : signatures) {
            check_signature_entropy_failure(test);
        }
        for (const KemCase& test : kems) {
            check_kem_entropy_failure(test);
        }
        active_drbg = nullptr;
        std::cout << "All 1,600 KAT records passed across 16 parameter sets.\n";
        return 0;
    } catch (const std::exception& error) {
        active_drbg = nullptr;
        std::cerr << "KAT failure: " << error.what() << '\n';
        return 1;
    }
}
