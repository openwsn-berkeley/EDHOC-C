add_compile_definitions(${EDHOC_CRYPTO_BACKEND})
add_compile_definitions(${EDHOC_CBOR_BACKEND})
add_compile_definitions(${EDHOC_X509_BACKEND})

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    link_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/lib)
    include_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/include)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS")
    link_directories(${CMAKE_BINARY_DIR}/3rdparty/mbedtls-build/lib)
    include_directories(${CMAKE_BINARY_DIR}/3rdparty/mbedtls-build/include)
endif ()

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    link_directories(${CMAKE_BINARY_DIR}/3rdparty/hacl-build/lib)
    include_directories(
            ${CMAKE_BINARY_DIR}/3rdparty/hacl-build/include
            ${CMAKE_BINARY_DIR}/3rdparty/hacl/dist/kremlin/include
            ${CMAKE_BINARY_DIR}/3rdparty/hacl/dist/kremlin/kremlib/dist/minimal)
endif ()

if ("${EDHOC_CBOR_BACKEND}" STREQUAL "NANOCBOR")
    link_directories(${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/lib)
    include_directories(${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/include)
endif ()

add_executable(fuzz-message1
        decode_msg1.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/credentials.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/ciphersuites.c
        ${PROJECT_SOURCE_DIR}/src/edhoc.c
        ${PROJECT_SOURCE_DIR}/src/format.c
        ${PROJECT_SOURCE_DIR}/src/process.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/tinycrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_decrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_encrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hkdf.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac_prng.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ccm_mode.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/utils.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha256.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/fprime.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha512.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ed25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/c25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/f25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/morph25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/edsign.c)

add_dependencies(fuzz-message1 nanocbor-backend)
target_link_libraries(fuzz-message1 PRIVATE nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(fuzz-message1 PRIVATE wolfssl)
    add_dependencies(fuzz-message1 wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(fuzz-message1 PRIVATE evercrypt)
    add_dependencies(fuzz-message1 hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS")
    add_dependencies(fuzz-message1 mbedtls-backend)
    target_link_libraries(fuzz-message1 PRIVATE mbedx509)
endif ()

target_include_directories(fuzz-message1 PRIVATE ../src ../include)


add_executable(fuzz-message2
        decode_msg2.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/credentials.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/ciphersuites.c
        ${PROJECT_SOURCE_DIR}/src/edhoc.c
        ${PROJECT_SOURCE_DIR}/src/format.c
        ${PROJECT_SOURCE_DIR}/src/process.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/tinycrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_decrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_encrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hkdf.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac_prng.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ccm_mode.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/utils.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha256.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/fprime.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha512.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ed25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/c25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/f25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/morph25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/edsign.c)

add_dependencies(fuzz-message2 nanocbor-backend)
target_link_libraries(fuzz-message2 PRIVATE nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(fuzz-message2 PRIVATE wolfssl)
    add_dependencies(fuzz-message2 wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(fuzz-message2 PRIVATE evercrypt)
    add_dependencies(fuzz-message2 hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS")
    add_dependencies(fuzz-message2 mbedtls-backend)
    target_link_libraries(fuzz-message2 PRIVATE mbedx509)
endif ()

target_include_directories(fuzz-message2 PRIVATE ../src ../include)
