cmake_minimum_required(VERSION 3.20)
project(kpqc VERSION 0.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(KPQC_BUILD_TESTS "Build KpqC tests" OFF)

set(PQC_FIPS202_SYMBOLS
    sha3_256 sha3_256_inc_absorb sha3_256_inc_ctx_clone
    sha3_256_inc_ctx_release sha3_256_inc_finalize sha3_256_inc_init
    sha3_384 sha3_384_inc_absorb sha3_384_inc_ctx_clone
    sha3_384_inc_ctx_release sha3_384_inc_finalize sha3_384_inc_init
    sha3_512 sha3_512_inc_absorb sha3_512_inc_ctx_clone
    sha3_512_inc_ctx_release sha3_512_inc_finalize sha3_512_inc_init
    shake128 shake128_absorb shake128_ctx_clone shake128_ctx_release
    shake128_inc_absorb shake128_inc_ctx_clone shake128_inc_ctx_release
    shake128_inc_finalize shake128_inc_init shake128_inc_squeeze
    shake128_squeezeblocks shake256 shake256_absorb shake256_ctx_clone
    shake256_ctx_release shake256_inc_absorb shake256_inc_ctx_clone
    shake256_inc_ctx_release shake256_inc_finalize shake256_inc_init
    shake256_inc_squeeze shake256_squeezeblocks)

set(COMPACT_FIPS202_SYMBOLS
    KeccakF_RoundConstants sha3_256 sha3_512 shake128 shake128_absorb
    shake128_absorb_once shake128_finalize shake128_init shake128_squeeze
    shake128_squeezeblocks shake256 shake256_absorb shake256_absorb_once
    shake256_finalize shake256_init shake256_squeeze shake256_squeezeblocks)

set(NTRUPLUS_SYMBOLS
    baseinv basemul basemul_add crypto_kem_dec crypto_kem_enc
    crypto_kem_keypair hash_f hash_g hash_h invntt ntt poly_baseinv
    poly_basemul poly_basemul_add poly_cbd1 poly_crepmod3 poly_frombytes
    poly_invntt poly_ntt poly_sotp_decode poly_sotp_encode poly_sub
    poly_tobytes poly_triple zetas)

set(HAETAE_SYMBOLS
    brv8 fix_round hammingWeight_8 polyfixfix_sub sample_gauss
    shake128_stream_init shake256_absorb_thrice shake256_absorb_twice
    shake256_stream_init start_cube start_times_threehalves)

set(SMAUGT_SYMBOLS flipabs shake256_absorb_twice_squeeze)

function(kpqc_rename_symbols target name)
    foreach(symbol IN LISTS ARGN)
        target_compile_definitions(${target} PRIVATE
            "${symbol}=kpqc_${name}_${symbol}")
    endforeach()
endfunction()

function(kpqc_object_library target group name random_source wrapper include_dir)
    add_library(${target} OBJECT ${wrapper} ${random_source} ${ARGN})
    target_include_directories(${target} PRIVATE ${include_dir})
    target_compile_definitions(${target} PRIVATE
        "KPQC_PREFIX=kpqc_${name}_"
        "randombytes=kpqc_${name}_randombytes")
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
        set_source_files_properties(${ARGN} PROPERTIES COMPILE_OPTIONS /W0)
    else()
        target_compile_options(${target} PRIVATE
            -fvisibility=hidden -Wall -Wextra -Wpedantic -Werror)
        set_source_files_properties(${ARGN} PROPERTIES
            COMPILE_OPTIONS "-fno-strict-aliasing;-w")
    endif()
    set_property(GLOBAL APPEND PROPERTY "KPQC_${group}_OBJECT_TARGETS" ${target})
endfunction()

function(kpqc_add_aimer group parameter random_source)
    set(name "aimer${parameter}")
    set(target "kpqc_${group}_${name}")
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/AIMer")
    string(SUBSTRING "${parameter}" 0 3 field_size)
    kpqc_object_library(${target} ${group} ${name} ${random_source}
        native/signature.c ${root}
        ${root}/aim3.c
        ${root}/field_common.c
        ${root}/hash.c
        ${root}/sign.c
        ${root}/tree.c
        ${root}/field${field_size}.c
        ${root}/common/fips202.c)
    target_include_directories(${target} PRIVATE ${root}/common)
    target_compile_definitions(${target} PRIVATE PARAMS=${parameter} KPQC_AIMER=1)
    kpqc_rename_symbols(${target} ${name}
        crypto_sign_keypair_internal crypto_sign_signature_internal
        crypto_sign_verify_internal ${PQC_FIPS202_SYMBOLS})
endfunction()

function(kpqc_add_haetae group name mode random_source)
    set(target "kpqc_${group}_${name}")
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/HAETAE")
    set(sources)
    foreach(source decompose encoding fft fixpoint ntt packing poly polyfix
                   polymat polyvec reduce sampler sign fips202 symmetric-shake)
        list(APPEND sources "${root}/src/${source}.c")
    endforeach()
    kpqc_object_library(${target} ${group} ${name} ${random_source}
        native/signature.c ${root}/include ${sources})
    target_compile_definitions(${target} PRIVATE HAETAE_CONFIG_MODE=${mode})
    kpqc_rename_symbols(${target} ${name}
        ${COMPACT_FIPS202_SYMBOLS} ${HAETAE_SYMBOLS})
endfunction()

function(kpqc_add_ntruplus group parameter random_source)
    set(name "ntruplus${parameter}")
    set(target "kpqc_${group}_${name}")
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/NTRUplus/NTRU+${parameter}")
    kpqc_object_library(${target} ${group} ${name} ${random_source}
        native/kem.c ${root}
        ${root}/kem.c
        ${root}/ntt.c
        ${root}/poly.c
        ${root}/symmetric.c
        ${root}/fips202/fips202.c)
    kpqc_rename_symbols(${target} ${name}
        ${NTRUPLUS_SYMBOLS} ${PQC_FIPS202_SYMBOLS})
endfunction()

function(kpqc_add_smaugt group name mode random_source)
    set(target "kpqc_${group}_${name}")
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/SMAUG-T")
    set(sources)
    foreach(source cbd ciphertext dg hash hwt indcpa kem key pack packring
                   poly toomcook verify fips202)
        list(APPEND sources "${root}/src/${source}.c")
    endforeach()
    kpqc_object_library(${target} ${group} ${name} ${random_source}
        native/kem.c ${root}/include ${sources})
    target_compile_definitions(${target} PRIVATE SMAUGT_CONFIG_MODE=${mode})
    kpqc_rename_symbols(${target} ${name}
        ${COMPACT_FIPS202_SYMBOLS} ${SMAUGT_SYMBOLS})
endfunction()

function(kpqc_configure_core group random_source output_variable)
    foreach(parameter 128f 128s 192f 192s 256f 256s)
        kpqc_add_aimer(${group} ${parameter} ${random_source})
    endforeach()

    kpqc_add_haetae(${group} haetae2 0 ${random_source})
    kpqc_add_haetae(${group} haetae3 1 ${random_source})
    kpqc_add_haetae(${group} haetae5 2 ${random_source})

    foreach(parameter 768 864 1152)
        kpqc_add_ntruplus(${group} ${parameter} ${random_source})
    endforeach()

    kpqc_add_smaugt(${group} smaugt128 0 ${random_source})
    kpqc_add_smaugt(${group} smaugt192 1 ${random_source})
    kpqc_add_smaugt(${group} smaugt256 2 ${random_source})
    kpqc_add_smaugt(${group} timer 3 ${random_source})

    get_property(object_targets GLOBAL PROPERTY "KPQC_${group}_OBJECT_TARGETS")
    set(objects)
    foreach(target IN LISTS object_targets)
        list(APPEND objects $<TARGET_OBJECTS:${target}>)
    endforeach()
    set(${output_variable} ${objects} PARENT_SCOPE)
endfunction()

function(kpqc_configure_cpp_target target)
    target_compile_features(${target} PUBLIC cxx_std_17)
    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
        target_link_libraries(${target} PUBLIC bcrypt)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
        if(UNIX AND NOT APPLE)
            target_link_libraries(${target} PUBLIC m)
        endif()
    endif()
endfunction()

kpqc_configure_core(production native/randombytes.c production_objects)
set(KPQC_CPP_SOURCES
    src/kpqc.cpp
    src/aimer.cpp
    src/haetae.cpp
    src/ntruplus.cpp
    src/smaugt.cpp)
add_library(kpqc STATIC ${KPQC_CPP_SOURCES} ${production_objects})
add_library(kpqc::kpqc ALIAS kpqc)
kpqc_configure_cpp_target(kpqc)
set_target_properties(kpqc PROPERTIES OUTPUT_NAME kpqc)

if(KPQC_BUILD_TESTS)
    enable_testing()
    kpqc_configure_core(test native/randombytes_test.c test_objects)
    add_library(kpqc_test_core STATIC EXCLUDE_FROM_ALL
        ${KPQC_CPP_SOURCES} ${test_objects})
    kpqc_configure_cpp_target(kpqc_test_core)

    add_executable(kpqc_api_test tests/api_test.cpp)
    target_link_libraries(kpqc_api_test PRIVATE kpqc)
    kpqc_configure_cpp_target(kpqc_api_test)
    add_test(NAME api COMMAND kpqc_api_test)

    add_executable(kpqc_kat_test
        tests/kat_test.cpp
        tests/kat_drbg.cpp)
    target_link_libraries(kpqc_kat_test PRIVATE kpqc_test_core)
    target_include_directories(kpqc_kat_test PRIVATE tests)
    target_compile_definitions(kpqc_kat_test PRIVATE
        "KPQC_DEFAULT_VECTOR_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/../kpqc-test-vectors\"")
    kpqc_configure_cpp_target(kpqc_kat_test)
    add_test(NAME kat COMMAND kpqc_kat_test)
endif()

install(TARGETS kpqc EXPORT kpqcTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE THIRD_PARTY_NOTICES.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/kpqc)
foreach(component AIMer HAETAE NTRUplus SMAUG-T)
    install(FILES "vendor/${component}/LICENSE"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/kpqc/licenses/${component}")
endforeach()

configure_package_config_file(
    cmake/kpqcConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/kpqcConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/kpqc")
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/kpqcConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion)

install(EXPORT kpqcTargets
    FILE kpqcTargets.cmake
    NAMESPACE kpqc::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/kpqc")
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/kpqcConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/kpqcConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/kpqc")
