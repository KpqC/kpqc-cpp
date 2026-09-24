#ifndef KPQC_TESTS_KAT_DRBG_HPP
#define KPQC_TESTS_KAT_DRBG_HPP

#include "kpqc/kpqc.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace kpqc::test {

using AesKey = std::array<std::uint8_t, 32>;
using AesBlock = std::array<std::uint8_t, 16>;

AesBlock aes256_encrypt(const AesKey& key, const AesBlock& block);

class CtrDrbg final {
public:
    explicit CtrDrbg(const Bytes& entropy_input);

    Bytes generate(std::size_t length);

private:
    void increment_counter() noexcept;
    void update(const std::uint8_t* provided_data);

    AesKey key_{};
    AesBlock counter_{};
};

}  // namespace kpqc::test

#endif
