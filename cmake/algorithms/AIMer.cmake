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
    target_compile_definitions(${target} PRIVATE
        PARAMS=${parameter}
        KPQC_AIMER=1)
    kpqc_rename_symbols(${target} ${name}
        crypto_sign_keypair_internal
        crypto_sign_signature_internal
        crypto_sign_verify_internal
        ${KPQC_FIPS202_SYMBOLS})
endfunction()
