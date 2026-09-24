#include "kat_drbg.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace kpqc::test {
namespace {

std::uint8_t gf_multiply(std::uint8_t left, std::uint8_t right) noexcept {
    std::uint8_t result = 0;
    for (int bit = 0; bit < 8; ++bit) {
        if ((right & 1U) != 0U) {
            result = static_cast<std::uint8_t>(result ^ left);
        }
        const bool high = (left & 0x80U) != 0U;
        left = static_cast<std::uint8_t>(left << 1U);
        if (high) {
            left = static_cast<std::uint8_t>(left ^ 0x1bU);
        }
        right = static_cast<std::uint8_t>(right >> 1U);
    }
    return result;
}

std::uint8_t gf_power(std::uint8_t value, unsigned exponent) noexcept {
    std::uint8_t result = 1;
    while (exponent != 0U) {
        if ((exponent & 1U) != 0U) {
            result = gf_multiply(result, value);
        }
        value = gf_multiply(value, value);
        exponent >>= 1U;
    }
    return result;
}

std::uint8_t rotate_left(std::uint8_t value, unsigned shift) noexcept {
    return static_cast<std::uint8_t>(
        (static_cast<unsigned>(value) << shift) |
        (static_cast<unsigned>(value) >> (8U - shift)));
}

std::uint8_t substitute(std::uint8_t value) noexcept {
    const std::uint8_t inverse = value == 0 ? 0 : gf_power(value, 254);
    return static_cast<std::uint8_t>(
        inverse ^ rotate_left(inverse, 1) ^ rotate_left(inverse, 2) ^
        rotate_left(inverse, 3) ^ rotate_left(inverse, 4) ^ 0x63U);
}

const std::array<std::uint8_t, 256>& sbox() {
    static const std::array<std::uint8_t, 256> values = [] {
        std::array<std::uint8_t, 256> result{};
        for (std::size_t index = 0; index < result.size(); ++index) {
            result[index] = substitute(static_cast<std::uint8_t>(index));
        }
        return result;
    }();
    return values;
}

using Word = std::array<std::uint8_t, 4>;
using RoundKey = std::array<std::uint8_t, 16>;

std::array<RoundKey, 15> round_keys(const AesKey& key) {
    std::array<Word, 60> words{};
    for (std::size_t index = 0; index < 8; ++index) {
        std::copy_n(key.begin() + static_cast<std::ptrdiff_t>(index * 4), 4,
                    words[index].begin());
    }

    std::uint8_t round_constant = 1;
    for (std::size_t index = 8; index < words.size(); ++index) {
        Word temporary = words[index - 1];
        if (index % 8 == 0) {
            temporary = {
                sbox()[temporary[1]], sbox()[temporary[2]],
                sbox()[temporary[3]], sbox()[temporary[0]]};
            temporary[0] = static_cast<std::uint8_t>(
                temporary[0] ^ round_constant);
            round_constant = gf_multiply(round_constant, 2);
        } else if (index % 8 == 4) {
            for (std::uint8_t& value : temporary) {
                value = sbox()[value];
            }
        }
        for (std::size_t byte = 0; byte < temporary.size(); ++byte) {
            words[index][byte] = static_cast<std::uint8_t>(
                words[index - 8][byte] ^ temporary[byte]);
        }
    }

    std::array<RoundKey, 15> result{};
    for (std::size_t round = 0; round < result.size(); ++round) {
        for (std::size_t word = 0; word < 4; ++word) {
            std::copy(words[round * 4 + word].begin(),
                      words[round * 4 + word].end(),
                      result[round].begin() +
                          static_cast<std::ptrdiff_t>(word * 4));
        }
    }
    return result;
}

void add_round_key(AesBlock& state, const RoundKey& key) noexcept {
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = static_cast<std::uint8_t>(state[index] ^ key[index]);
    }
}

void shift_rows(AesBlock& state) noexcept {
    const AesBlock source = state;
    state = {source[0], source[5], source[10], source[15],
             source[4], source[9], source[14], source[3],
             source[8], source[13], source[2], source[7],
             source[12], source[1], source[6], source[11]};
}

void mix_columns(AesBlock& state) noexcept {
    for (std::size_t offset = 0; offset < state.size(); offset += 4) {
        const std::uint8_t a = state[offset];
        const std::uint8_t b = state[offset + 1];
        const std::uint8_t c = state[offset + 2];
        const std::uint8_t d = state[offset + 3];
        state[offset] = static_cast<std::uint8_t>(
            gf_multiply(a, 2) ^ gf_multiply(b, 3) ^ c ^ d);
        state[offset + 1] = static_cast<std::uint8_t>(
            a ^ gf_multiply(b, 2) ^ gf_multiply(c, 3) ^ d);
        state[offset + 2] = static_cast<std::uint8_t>(
            a ^ b ^ gf_multiply(c, 2) ^ gf_multiply(d, 3));
        state[offset + 3] = static_cast<std::uint8_t>(
            gf_multiply(a, 3) ^ b ^ c ^ gf_multiply(d, 2));
    }
}

}  // namespace

AesBlock aes256_encrypt(const AesKey& key, const AesBlock& block) {
    const auto keys = round_keys(key);
    AesBlock state = block;
    add_round_key(state, keys[0]);
    for (std::size_t round = 1; round < 14; ++round) {
        for (std::uint8_t& value : state) {
            value = sbox()[value];
        }
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, keys[round]);
    }
    for (std::uint8_t& value : state) {
        value = sbox()[value];
    }
    shift_rows(state);
    add_round_key(state, keys[14]);
    return state;
}

CtrDrbg::CtrDrbg(const Bytes& entropy_input) {
    if (entropy_input.size() != 48) {
        throw std::invalid_argument("CTR DRBG entropy input must be 48 bytes");
    }
    update(entropy_input.data());
}

Bytes CtrDrbg::generate(std::size_t length) {
    Bytes output(length);
    std::size_t offset = 0;
    while (offset < output.size()) {
        increment_counter();
        const AesBlock block = aes256_encrypt(key_, counter_);
        const std::size_t count =
            std::min(block.size(), output.size() - offset);
        std::copy_n(block.begin(), static_cast<std::ptrdiff_t>(count),
                    output.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += count;
    }
    update(nullptr);
    return output;
}

void CtrDrbg::increment_counter() noexcept {
    for (auto cursor = counter_.rbegin(); cursor != counter_.rend(); ++cursor) {
        *cursor = static_cast<std::uint8_t>(*cursor + 1U);
        if (*cursor != 0) {
            break;
        }
    }
}

void CtrDrbg::update(const std::uint8_t* provided_data) {
    std::array<std::uint8_t, 48> material{};
    for (std::size_t offset = 0; offset < material.size(); offset += 16) {
        increment_counter();
        const AesBlock block = aes256_encrypt(key_, counter_);
        std::copy(block.begin(), block.end(),
                  material.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    if (provided_data != nullptr) {
        for (std::size_t index = 0; index < material.size(); ++index) {
            material[index] = static_cast<std::uint8_t>(
                material[index] ^ provided_data[index]);
        }
    }
    std::copy_n(material.begin(), key_.size(), key_.begin());
    std::copy_n(material.begin() + static_cast<std::ptrdiff_t>(key_.size()),
                counter_.size(), counter_.begin());
}

}  // namespace kpqc::test
