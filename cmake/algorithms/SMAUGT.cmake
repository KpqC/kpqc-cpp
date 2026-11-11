set(KPQC_SMAUGT_SYMBOLS flipabs shake256_absorb_twice_squeeze)

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
    target_compile_definitions(${target} PRIVATE
        SMAUGT_CONFIG_MODE=${mode}
        SMAUGT_CONFIG_NAMESPACE_PREFIX=kpqc_cryptolab_smaugt_)
    kpqc_rename_symbols(${target} ${name}
        ${KPQC_COMPACT_FIPS202_SYMBOLS}
        ${KPQC_SMAUGT_SYMBOLS})
endfunction()
