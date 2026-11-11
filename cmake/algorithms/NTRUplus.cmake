set(KPQC_NTRUPLUS_SYMBOLS
    baseinv basemul basemul_add crypto_kem_dec crypto_kem_enc
    crypto_kem_keypair hash_f hash_g hash_h invntt ntt poly_baseinv
    poly_basemul poly_basemul_add poly_cbd1 poly_crepmod3 poly_frombytes
    poly_invntt poly_ntt poly_sotp_decode poly_sotp_encode poly_sub
    poly_tobytes poly_triple zetas)

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
        ${KPQC_NTRUPLUS_SYMBOLS}
        ${KPQC_FIPS202_SYMBOLS})
endfunction()
