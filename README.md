# KpqC

KpqC provides typed, synchronous C++17 APIs for AIMer, HAETAE, NTRU+,
and SMAUG-T.

## Runtime support

- C++17 or newer
- macOS or Linux
- CMake 3.20 or newer and a C11 compiler when building from source

## Install

Build and install the static library, replacing `/path/to/prefix` with the
installation location:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
cmake --install build --prefix /path/to/prefix
```

Use the installed package from another CMake project:

```cmake
find_package(kpqc CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE kpqc::kpqc)
```

When the prefix is outside CMake's normal search locations, configure the
consumer with `-DCMAKE_PREFIX_PATH=/path/to/prefix`.

## Available schemes

| Algorithm | Type | Accessors |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f`, `aimer128s`, `aimer192f`, `aimer192s`, `aimer256f`, `aimer256s` |
| **HAETAE** | Signature | `haetae2`, `haetae3`, `haetae5` |
| **NTRU+** | Key encapsulation | `ntruplus768`, `ntruplus864`, `ntruplus1152` |
| **SMAUG&#8209;T** | Key encapsulation | `smaugt128`, `smaugt192`, `smaugt256`, `timer` |

Using an algorithm family namespace keeps the entry point focused:

```cpp
#include <kpqc/kpqc.hpp>

#include <stdexcept>

const kpqc::Bytes payload{
    'r', 'e', 'l', 'e', 'a', 's', 'e', '-',
    'm', 'a', 'n', 'i', 'f', 'e', 's', 't'};
const auto& algorithm = kpqc::aimer::aimer128f();
const kpqc::KeyPair keys = algorithm.generate_key_pair();
const kpqc::Bytes proof = algorithm.sign(payload, keys.secret_key);

if (!algorithm.verify(payload, proof, keys.public_key)) {
    throw std::runtime_error("signature verification failed");
}
```

### Signature contexts

AIMer and HAETAE accept an optional context. A context separates signatures
created for different application purposes and may contain up to 255 bytes.

```cpp
#include <kpqc/kpqc.hpp>

const kpqc::Bytes payload{'a', 'c', 'c', 'o', 'u', 'n', 't'};
const kpqc::Bytes context{'a', 'u', 'd', 'i', 't'};
const auto& algorithm = kpqc::haetae::haetae3();
const kpqc::KeyPair keys = algorithm.generate_key_pair();

const kpqc::Bytes signature =
    algorithm.sign(payload, keys.secret_key, context);
const bool valid =
    algorithm.verify(payload, signature, keys.public_key, context);
```

Verification fails when the supplied context does not match the one used for
signing.

### Key encapsulation

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```cpp
#include <kpqc/kpqc.hpp>

const auto& algorithm = kpqc::smaugt::smaugt192();
const kpqc::KeyPair recipient = algorithm.generate_key_pair();

const kpqc::EncapsulatedSecret outbound =
    algorithm.encapsulate(recipient.public_key);
// Send outbound.ciphertext to the recipient.

const kpqc::Bytes inbound_secret =
    algorithm.decapsulate(outbound.ciphertext, recipient.secret_key);

const bool matches = inbound_secret == outbound.shared_secret;  // true
```

## Imports

The public API is provided by one header. Algorithms are grouped by family
namespace:

```cpp
#include <kpqc/kpqc.hpp>

const kpqc::SignatureAlgorithm& signer = kpqc::aimer::aimer192f();
const kpqc::KeyEncapsulationAlgorithm& key_exchange =
    kpqc::ntruplus::ntruplus864();
```

## Data and failures

Binary inputs and outputs use `kpqc::Bytes`, an alias for
`std::vector<std::uint8_t>`. Each algorithm exposes `id()` and `sizes()`.

Wrong-sized inputs and contexts over 255 bytes raise `std::invalid_argument`.
Signature verification returns `false` for an invalid signature. Native
failures raise `kpqc::Error`, which exposes the failed operation and status
code.

NTRU+ rejects non-canonical public keys and invalid ciphertexts. SMAUG-T uses
implicit rejection for an invalid ciphertext and returns a replacement secret;
that value will not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Accessor | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `aimer128f` | 32 | 48 | 6,944 |
| `aimer128s` | 32 | 48 | 4,704 |
| `aimer192f` | 48 | 72 | 15,408 |
| `aimer192s` | 48 | 72 | 10,320 |
| `aimer256f` | 64 | 96 | 31,360 |
| `aimer256s` | 64 | 96 | 20,224 |
| `haetae2` | 992 | 1,408 | 1,474 |
| `haetae3` | 1,472 | 2,112 | 2,349 |
| `haetae5` | 2,080 | 2,752 | 2,948 |

#### Key encapsulation

| Accessor | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `ntruplus768` | 1,152 | 2,336 | 1,152 | 32 |
| `ntruplus864` | 1,296 | 2,624 | 1,296 | 32 |
| `ntruplus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `smaugt128` | 672 | 832 | 672 | 32 |
| `smaugt192` | 1,088 | 1,312 | 992 | 32 |
| `smaugt256` | 1,440 | 1,728 | 1,376 | 32 |
| `timer` | 672 | 832 | 608 | 32 |

## Known-answer tests

The implementation is tested against all 1,600 KAT records in
[KpqC/kpqc-test-vectors at commit 179dcc05ece2](https://github.com/KpqC/kpqc-test-vectors/tree/179dcc05ece2e22262cea1a61f3cdf1a5b08a304).
The tests use a sibling `kpqc-test-vectors` checkout by default, or the path in
`KPQC_TEST_VECTORS`. The vector files are not duplicated in this repository.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DKPQC_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Distribution

The installation includes a static library, the public C++ header, CMake
package files, and the applicable license notices. It has no third-party
runtime dependencies.

## Security

The native cores are compiled from the upstream algorithm implementations.
This package has not received an independent security audit and does not
provide a constant-time execution guarantee. Assess those constraints before
using it with sensitive production keys.

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](https://github.com/KpqC/kpqc-cpp/blob/main/THIRD_PARTY_NOTICES.md).
