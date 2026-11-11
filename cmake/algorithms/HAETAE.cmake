set(KPQC_HAETAE_SYMBOLS
    brv8 fix_round hammingWeight_8 polyfixfix_sub sample_gauss
    shake128_stream_init shake256_absorb_thrice shake256_absorb_twice
    shake256_stream_init start_cube start_times_threehalves)

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
    target_compile_definitions(${target} PRIVATE
        HAETAE_CONFIG_MODE=${mode}
        HAETAE_CONFIG_NAMESPACE_PREFIX=kpqc_cryptolab_haetae_)
    kpqc_rename_symbols(${target} ${name}
        ${KPQC_COMPACT_FIPS202_SYMBOLS}
        ${KPQC_HAETAE_SYMBOLS})
endfunction()
