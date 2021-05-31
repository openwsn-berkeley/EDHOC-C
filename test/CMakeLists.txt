# unit tests for EDHOC

add_compile_definitions(${EDHOC_CRYPTO_BACKEND})
add_compile_definitions(${EDHOC_CBOR_BACKEND})
add_compile_definitions(${EDHOC_X509_BACKEND})

include(cjson)

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

# create all test executables

###################################################################
# CRYPTO
###################################################################

add_executable(test-crypto
        json.c
        test_crypto.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_decrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_encrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hkdf.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac_prng.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ccm_mode.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/utils.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha256.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/fprime.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/sha512.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/ed25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/c25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/f25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/morph25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/edsign.c)

add_dependencies(test-crypto json-parser nanocbor-backend)
target_link_libraries(test-crypto PRIVATE cjson nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-crypto PRIVATE wolfssl)
    add_dependencies(test-crypto wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-crypto PRIVATE evercrypt)
    add_dependencies(test-crypto hacl-backend)
endif ()

target_include_directories(test-crypto PRIVATE ../src ../include)

###################################################################
# EDHOC
###################################################################

add_executable(test-edhoc
        json.c
        test_edhoc.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/credentials.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/ciphersuites.c
        ${PROJECT_SOURCE_DIR}/src/edhoc.c
        ${PROJECT_SOURCE_DIR}/src/format.c
        ${PROJECT_SOURCE_DIR}/src/creddb.c
        ${PROJECT_SOURCE_DIR}/src/process.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_decrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_encrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hkdf.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac_prng.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ccm_mode.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/utils.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha256.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/fprime.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/sha512.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/ed25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/c25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/f25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/morph25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/edsign.c)

add_dependencies(test-edhoc json-parser nanocbor-backend)
target_link_libraries(test-edhoc PRIVATE cjson nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-edhoc PRIVATE wolfssl)
    add_dependencies(test-edhoc wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-edhoc PRIVATE evercrypt)
    add_dependencies(test-edhoc hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS")
    add_dependencies(test-edhoc mbedtls-backend)
    target_link_libraries(test-edhoc PRIVATE mbedx509)
endif ()

target_include_directories(test-edhoc PRIVATE ../src ../include)


###################################################################
# FORMATTING
###################################################################

add_executable(test-format
        test_format.c
        json.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/ciphersuites.c
        ${PROJECT_SOURCE_DIR}/src/format.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_decrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_encrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hkdf.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac_prng.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ccm_mode.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/utils.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha256.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/fprime.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/sha512.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/ed25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/c25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/f25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/morph25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/edsign.c)

add_dependencies(test-format json-parser nanocbor-backend)
target_link_libraries(test-format PRIVATE cjson nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-format PRIVATE wolfssl)
    add_dependencies(test-format wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-format PRIVATE evercrypt)
    add_dependencies(test-format hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS")
    add_dependencies(test-format mbedtls-backend)
    target_link_libraries(test-format PRIVATE mbedx509)
endif ()

target_include_directories(test-format PRIVATE ../src ../include)

###################################################################
# CREDENTIALS
###################################################################

add_executable(test-credentials
        test_credentials.c
        json.c
        ${PROJECT_SOURCE_DIR}/src/credentials.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_decrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_encrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hkdf.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac_prng.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ccm_mode.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/utils.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha256.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/fprime.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/sha512.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/ed25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/c25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/f25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/morph25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/edsign.c)

add_dependencies(test-credentials json-parser nanocbor-backend)
target_link_libraries(test-credentials PRIVATE cjson nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-credentials PRIVATE wolfssl)
    add_dependencies(test-credentials wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-credentials PRIVATE evercrypt)
    add_dependencies(test-credentials hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS")
    add_dependencies(test-edhoc mbedtls-backend)
    target_link_libraries(test-credentials PRIVATE mbedx509)
endif ()

target_include_directories(test-credentials PRIVATE ../src ../include)

###################################################################
# PROCESSING
###################################################################

add_executable(test-process
        json.c
        test_process.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/credentials.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/ciphersuites.c
        ${PROJECT_SOURCE_DIR}/src/edhoc.c
        ${PROJECT_SOURCE_DIR}/src/format.c
        ${PROJECT_SOURCE_DIR}/src/creddb.c
        ${PROJECT_SOURCE_DIR}/src/process.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_decrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/aes_encrypt.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hkdf.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/hmac_prng.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/ccm_mode.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/utils.c
        ${PROJECT_SOURCE_DIR}/src/crypto/tinycrypt/sha256.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/fprime.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/sha512.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/ed25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/c25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/f25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/morph25519.c
        ${PROJECT_SOURCE_DIR}/src/crypto/c25519/edsign.c)

add_dependencies(test-process json-parser nanocbor-backend)
target_link_libraries(test-process PRIVATE cjson nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-process PRIVATE wolfssl)
    add_dependencies(test-process wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-process PRIVATE evercrypt)
    add_dependencies(test-process hacl-backend)
endif ()

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS")
    add_dependencies(test-process mbedtls-backend)
    target_link_libraries(test-process PRIVATE mbedx509)
endif ()

target_include_directories(test-process PRIVATE ../src ../include)

###########################################################

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg1 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg1 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg2 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg2 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg2 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg2 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_FORMAT_MESSAGE_3_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg3 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_ENCODE_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --encode-msg3 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg3 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-format --decode-msg3 test_vectors/vector4.json
)

###################################################################
# CREDENTIALS
###################################################################

add_test(
        NAME TEST_CRED_CERT_FROM_CBOR_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-credentials --cert-from-cbor test_vectors/cborCert1.json
)

add_test(
        NAME TEST_CRED_CERT_FROM_CBOR_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-credentials --cert-from-cbor test_vectors/cborCert2.json
)

add_test(
        NAME TEST_CRED_RPK_FROM_CBOR_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-credentials --rpk-from-cbor test_vectors/rpk1.json
)

add_test(
        NAME TEST_CRED_ID_FROM_CBOR_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-credentials --cred-id-from-cbor test_vectors/vector1.json
)

add_test(
        NAME TEST_CRED_ID_FROM_CBOR_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-credentials --cred-id-from-cbor test_vectors/vector2.json
)

###################################################################
# PROCESSING
###################################################################

add_test(
        NAME TEST_PROCESS_MESSAGE_1_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg1 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_PROCESS_MESSAGE_2_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg2 test_vectors/vector3.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg2 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_PROCESS_MESSAGE_3_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg3 test_vectors/vector3.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --create-msg3 test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_PROCESS_RESPONDER_FINALIZE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --finalize-responder test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_RESPONDER_FINALIZE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --finalize-responder test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_RESPONDER_FINALIZE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --finalize-responder test_vectors/vector3.json
)

add_test(
        NAME TEST_PROCESS_RESPONDER_FINALIZE_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-process --finalize-responder test_vectors/vector4.json
)

###################################################################
# CRYPTO
###################################################################

add_test(
        NAME TEST_CRYPTO_HASHING_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --hashing test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --hashing test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --hashing test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --hashing test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_CRYPTO_EDSIGN_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --edsign test_vectors/vector1.json
)

# --

add_test(
        NAME TEST_CRYPTO_PRK_ECDH_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --ecdh-hmac test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_PRK_ECDH_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --ecdh-hmac test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_PRK_ECDH_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --ecdh-hmac test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_PRK_ECDH_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --ecdh-hmac test_vectors/vector4.json
)

# --

add_test(
        NAME TEST_CRYPTO_KDF_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --kdf test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_KDF_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --kdf test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_KDF_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --kdf test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_KDF_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-crypto --kdf test_vectors/vector4.json
)

###################################################################
# EDHOC
###################################################################

add_test(
        NAME TEST_EDHOC_EXPORTER_SECRET_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-secret test_vectors/vector1.json
)

add_test(
        NAME TEST_EDHOC_EXPORTER_SALT_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-salt test_vectors/vector1.json
)

# --

add_test(
        NAME TEST_EDHOC_EXPORTER_SECRET_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-secret test_vectors/vector2.json
)

add_test(
        NAME TEST_EDHOC_EXPORTER_SALT_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-salt test_vectors/vector2.json
)

# --

add_test(
        NAME TEST_EDHOC_EXPORTER_SECRET_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-secret test_vectors/vector2.json
)

add_test(
        NAME TEST_EDHOC_EXPORTER_SALT_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-salt test_vectors/vector3.json
)

# --

add_test(
        NAME TEST_EDHOC_EXPORTER_SECRET_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-secret test_vectors/vector4.json
)

add_test(
        NAME TEST_EDHOC_EXPORTER_SALT_V4
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test-edhoc --export-salt test_vectors/vector4.json
)
