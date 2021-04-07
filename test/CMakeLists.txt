# unit tests for EDHOC

add_compile_definitions(${EDHOC_CRYPTO_BACKEND})
add_compile_definitions(${EDHOC_CBOR_BACKEND})
add_compile_definitions(${EDHOC_X509_BACKEND})

include(cjson)

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

# create all test executables

###################################################################
# EDHOC
###################################################################

add_executable(test-edhoc
        util.c
        json.c
        test_edhoc.c
        ../src/cbor/nanocbor.c
        ../src/credentials.c
        ../src/cose.c
        ../src/ciphersuites.c
        ../src/edhoc.c
        ../src/format.c
        ../src/creddb.c
        ../src/process.c
        ../src/crypto/wolfssl.c
        ../src/crypto/aes128.c
        ../src/crypto/ccm.c
        ../src/crypto/hacl.c
        ../src/crypto/aes128.c
        ../src/crypto/ccm.c)

add_dependencies(test-edhoc nanocbor-backend)
target_link_libraries(test-edhoc PRIVATE nanocbor)

add_dependencies(test-edhoc json-parser)
target_link_libraries(test-edhoc PRIVATE cjson)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-edhoc PRIVATE wolfssl)
    add_dependencies(test-edhoc wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-edhoc PRIVATE evercrypt)
    add_dependencies(test-edhoc hacl-backend)
endif ()

add_dependencies(test-edhoc mbedtls-backend)
target_link_libraries(test-edhoc PRIVATE mbedx509)
target_link_libraries(test-edhoc PRIVATE mbedtls)
target_link_libraries(test-edhoc PRIVATE mbedcrypto)

target_include_directories(test-edhoc PRIVATE ../src ../include)


###################################################################
# FORMATTING
###################################################################

add_executable(test-format
        test_format.c
        util.c
        json.c
        ../src/cose.c
        ../src/cipher_suites.c
        ../src/format.c
        ../src/crypto/wolfssl.c
        ../src/crypto/hacl.c
        ../src/cbor/nanocbor.c)

add_dependencies(test-format nanocbor-backend)
target_link_libraries(test-format PRIVATE nanocbor)

add_dependencies(test-format json-parser)
target_link_libraries(test-format PRIVATE cjson)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-format PRIVATE wolfssl)
    add_dependencies(test-format wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-format PRIVATE evercrypt)
    add_dependencies(test-format hacl-backend)
endif ()

add_dependencies(test-format mbedtls-backend)
target_link_libraries(test-format PRIVATE mbedx509)
target_link_libraries(test-format PRIVATE mbedtls)
target_link_libraries(test-format PRIVATE mbedcrypto)

target_include_directories(test-format PRIVATE ../src ../include)

###################################################################
# CREDENTIALS
###################################################################

add_executable(test-credentials
        test_credentials.c
        util.c
        json.c
        ../src/credentials.c
        ../src/cose.c
        ../src/crypto/wolfssl.c
        ../src/crypto/hacl.c
        ../src/cbor/nanocbor.c)

add_dependencies(test-credentials nanocbor-backend)
target_link_libraries(test-credentials PRIVATE nanocbor)

add_dependencies(test-credentials mbedtls-backend)
target_link_libraries(test-credentials PRIVATE mbedx509)
target_link_libraries(test-credentials PRIVATE mbedtls)
target_link_libraries(test-credentials PRIVATE mbedcrypto)

add_dependencies(test-credentials json-parser)
target_link_libraries(test-credentials PRIVATE cjson)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-credentials PRIVATE wolfssl)
    add_dependencies(test-credentials wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-credentials PRIVATE evercrypt)
    add_dependencies(test-credentials hacl-backend)
endif ()

target_include_directories(test-credentials PRIVATE ../src ../include)

###################################################################
# PROCESSING
###################################################################

add_executable(test-process
        util.c
        json.c
        test_process.c
        ../src/cbor/nanocbor.c
        ../src/credentials.c
        ../src/cose.c
        ../src/cipher_suites.c
        ../src/edhoc.c
        ../src/format.c
        ../src/creddb.c
        ../src/process.c
        ../src/crypto/wolfssl.c
        ../src/crypto/hacl.c
        ../src/crypto/aes128.c
        ../src/crypto/ccm.c)

add_dependencies(test-process nanocbor-backend)
target_link_libraries(test-process PRIVATE nanocbor)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(test-process PRIVATE wolfssl)
    add_dependencies(test-process wolfssl-backend)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    target_link_libraries(test-process PRIVATE evercrypt)
    add_dependencies(test-process hacl-backend)
endif ()

add_dependencies(test-process mbedtls-backend)
target_link_libraries(test-process PRIVATE mbedx509)
target_link_libraries(test-process PRIVATE mbedtls)
target_link_libraries(test-process PRIVATE mbedcrypto)

add_dependencies(test-process json-parser)

target_include_directories(test-process PRIVATE ../src ../include)
target_link_libraries(test-process PRIVATE cjson)

# ###################################################################
# # CRYPTO
# ###################################################################
#
# add_executable(test_crypto
#         test_crypto.c
#         util.c
#         json.c
#         ../src/edhoc.c
#         ../src/format.c
#         ../src/credentials.c
#         ../src/cbor/nanocbor.c
#         ../src/crypto/wolfssl.c
#         ../src/cose.c
#         ../src/cipher_suites.c
#         ../src/crypto/hacl.c
#         ../src/crypto/aes128.c
#         ../src/crypto/ccm.c)
#
# add_dependencies(test_crypto nanocbor-backend)
# target_link_libraries(test_crypto PRIVATE nanocbor)
#
# if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
#     add_dependencies(test_crypto wolfssl-backend)
#     target_link_libraries(test_crypto PRIVATE wolfssl)
# elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
#     add_dependencies(test_crypto hacl-backend)
#     target_link_libraries(test_crypto PRIVATE evercrypt)
# endif ()
#
# add_dependencies(test_crypto json-parser)
# target_link_libraries(test_crypto PRIVATE cjson)
#
# target_include_directories(test_crypto PRIVATE ../src ../include)
#
# ###################################################################
# # CBOR
# ###################################################################
#
# add_executable(test_cbor
#         test_cbor.c
#         ../src/cbor/nanocbor.c
#         util.c
#         json.c)
#
# add_dependencies(test_cbor nanocbor-backend)
# target_link_libraries(test_cbor PRIVATE nanocbor)
#
# add_dependencies(test_cbor json-parser)
# target_link_libraries(test_cbor PRIVATE cjson)
#
# target_include_directories(test_cbor PRIVATE ../src ../include)

###################################################################
# FORMATTING
###################################################################

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
