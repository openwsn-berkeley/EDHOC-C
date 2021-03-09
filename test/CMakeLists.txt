# unit tests for EDHOC

add_compile_definitions(${EDHOC_CRYPTO_BACKEND})
add_compile_definitions(${EDHOC_CBOR_BACKEND})

include(cjson)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    link_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/lib)
    include_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/include)
endif ()

if ("${EDHOC_CBOR_BACKEND}" STREQUAL "NANOCBOR")
    link_directories(${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/lib)
    include_directories(${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/include)
endif ()

# create all test executables

###################################################################
# FORMATTING
###################################################################

add_executable(test_format
        test_format.c
        util.c
        json.c
        ../src/cipher_suites.c
        ../src/cose.c
        ../src/format.c
        ../src/cbor/nanocbor.c)

add_dependencies(test_format nanocbor-backend)
add_dependencies(test_format json-parser)

target_include_directories(test_format PRIVATE ../src ../include)
target_link_libraries(test_format PRIVATE cjson nanocbor)

###################################################################
# PROCESSING
###################################################################

add_executable(test_process
        test_process.c
        util.c
        json.c
        ../src/cbor/nanocbor.c
        ../src/cose.c
        ../src/cipher_suites.c
        ../src/credentials.c
        ../src/edhoc.c
        ../src/format.c
        ../src/process.c
        ../src/crypto/wolfssl.c
        ../src/crypto/hacl.c
        ../src/crypto/aes128.c
        ../src/crypto/ccm.c)

add_dependencies(test_process nanocbor-backend)
add_dependencies(test_process wolfssl-backend)
add_dependencies(test_process json-parser)

target_include_directories(test_process PRIVATE ../src ../include)
target_link_libraries(test_process PRIVATE cjson wolfssl nanocbor)

###################################################################
# CRYPTO
###################################################################

add_executable(test_crypto
        test_crypto.c
        util.c
        json.c
        ../src/edhoc.c
        ../src/format.c
        ../src/credentials.c
        ../src/cbor/nanocbor.c
        ../src/crypto/wolfssl.c
        ../src/cose.c
        ../src/cipher_suites.c
        ../src/crypto/hacl.c
        ../src/crypto/aes128.c
        ../src/crypto/ccm.c)

add_dependencies(test_crypto nanocbor-backend)
add_dependencies(test_crypto wolfssl-backend)
add_dependencies(test_crypto json-parser)

target_link_libraries(test_crypto PRIVATE cjson wolfssl nanocbor)
target_include_directories(test_crypto PRIVATE ../src ../include)

###################################################################
# CBOR
###################################################################

add_executable(test_cbor
        test_cbor.c
        ../src/cbor/nanocbor.c
        util.c
        json.c)

add_dependencies(test_cbor nanocbor-backend)
add_dependencies(test_cbor json-parser)

target_link_libraries(test_cbor PRIVATE cjson nanocbor)
target_include_directories(test_cbor PRIVATE ../src ../include)


add_test(
        NAME TEST_CBOR_BYTES_DECODING
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_cbor --decoding-bytes test_vectors/cbor_bytes_decoding.json
)

add_test(
        NAME TEST_CBOR_BYTES_ENCODING
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_cbor --encoding-bytes test_vectors/cbor_bytes_encoding.json
)

add_test(
        NAME TEST_CBOR_SUITES_DECODING
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_cbor --decoding-suites test_vectors/cbor_suites_decoding.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-msg2 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg2 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_DATA_2_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-data2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_DATA_2_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-data2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_DATA_2_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-data2 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_INFO_K2M_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-k2m test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_INFO_K2M_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-k2m test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_INFO_K2M_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-k2m test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_INFO_IV2M_ENCODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-iv2m test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_INFO_IV2M_ENCODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-iv2m test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_INFO_IV2M_ENCODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-iv2m test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode-msg3 test_vectors/vector3.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg2 test_vectors/vector3.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg3 test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hashing test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hashing test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hashing test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_HMAC_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hmac test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_HMAC_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hmac test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_HMAC_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hmac test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2M_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2m test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2M_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2m test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2M_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2m test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_KDF_IV2M_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-iv2m test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_KDF_IV2M_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-iv2m test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_KDF_IV2M_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-iv2m test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2E_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2e test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2E_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2e test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2E_V3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2e test_vectors/vector3.json
)

add_test(
        NAME TEST_CRYPTO_ED25519_V1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --ed25519 test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_ED25519_V2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --ed25519 test_vectors/vector2.json
)

