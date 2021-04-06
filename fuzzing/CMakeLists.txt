add_compile_definitions(${EDHOC_CRYPTO_BACKEND})
add_compile_definitions(${EDHOC_CBOR_BACKEND})
add_compile_definitions(${EDHOC_X509_BACKEND})

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    link_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/lib)
    include_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/include)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS_X509")
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
        ../src/cbor/nanocbor.c
        ../src/credentials.c
        ../src/cose.c
        ../src/cipher_suites.c
        ../src/edhoc.c
        ../src/format.c
        ../src/process.c
        ../src/crypto/hacl.c
        ../src/crypto/aes128.c
        ../src/crypto/ccm.c
        ../src/crypto/wolfssl.c)

add_dependencies(fuzz-message1 nanocbor-backend)
target_link_libraries(fuzz-message1 PRIVATE nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(fuzz-message1 PRIVATE wolfssl)
    add_dependencies(fuzz-message1 wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(fuzz-message1 PRIVATE evercrypt)
    add_dependencies(fuzz-message1 hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS_X509")
    add_dependencies(fuzz-message1 mbedtls-backend)
    target_link_libraries(fuzz-message1 PRIVATE mbedx509)
    target_link_libraries(fuzz-message1 PRIVATE mbedtls)
    target_link_libraries(fuzz-message1 PRIVATE mbedcrypto)
endif ()

target_include_directories(fuzz-message1 PRIVATE ../src ../include)


add_executable(fuzz-message2
        decode_msg2.c
        ../src/cbor/nanocbor.c
        ../src/credentials.c
        ../src/cose.c
        ../src/cipher_suites.c
        ../src/edhoc.c
        ../src/format.c
        ../src/process.c
        ../src/crypto/hacl.c
        ../src/crypto/aes128.c
        ../src/crypto/ccm.c
        ../src/crypto/wolfssl.c)

add_dependencies(fuzz-message2 nanocbor-backend)
target_link_libraries(fuzz-message2 PRIVATE nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(fuzz-message2 PRIVATE wolfssl)
    add_dependencies(fuzz-message2 wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(fuzz-message2 PRIVATE evercrypt)
    add_dependencies(fuzz-message2 hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS_X509")
    add_dependencies(fuzz-message2 mbedtls-backend)
    target_link_libraries(fuzz-message2 PRIVATE mbedx509)
    target_link_libraries(fuzz-message2 PRIVATE mbedtls)
    target_link_libraries(fuzz-message2 PRIVATE mbedcrypto)
endif ()

target_include_directories(fuzz-message2 PRIVATE ../src ../include)
