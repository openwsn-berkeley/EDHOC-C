# unit tests for EDHOC

add_compile_definitions(${EDHOC_CRYPTO_BACKEND})

# create all executables
add_executable(test_internal test_internal.c util.c util.h json.h json.c)
target_link_libraries(test_internal PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_internal PRIVATE cjson)
target_include_directories(test_internal PRIVATE ../src)

add_executable(test_initiator test_initiator.c util.c util.h json.h json.c)
target_link_libraries(test_initiator PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_initiator PRIVATE cjson)

add_executable(test_responder test_responder.c util.c util.h json.h json.c)
target_link_libraries(test_responder PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_responder PRIVATE cjson)

add_executable(test_crypto test_crypto.c util.c util.h json.h json.c)
target_link_libraries(test_crypto PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_crypto PRIVATE cjson)
target_include_directories(test_crypto PRIVATE ../src/crypto)

add_executable(test_cose test_cose.c util.c util.h json.h json.c)
target_link_libraries(test_cose PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_cose PRIVATE cjson)

add_executable(test_cbor test_cbor.c util.c util.h json.h json.c)
target_link_libraries(test_cbor PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_cbor PRIVATE cjson)
target_include_directories(test_cbor PRIVATE ../src/cbor)


add_test(
        NAME TEST_MESSAGE_1_DECODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --decode_msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_MESSAGE_1_DECODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --decode_msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_DATA_2_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --encode-data2 test_vectors/vector1.json
)

add_test(
        NAME TEST_DATA_2_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --encode-data2 test_vectors/vector2.json
)

add_test(
        NAME TEST_INFO_K2M_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --encode-info-k2m test_vectors/vector1.json
)

add_test(
        NAME TEST_INFO_K2M_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --encode-info-k2m test_vectors/vector2.json
)

add_test(
        NAME TEST_INFO_IV2M_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --encode-info-iv2m test_vectors/vector1.json
)

add_test(
        NAME TEST_INFO_IV2M_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --encode-info-iv2m test_vectors/vector2.json
)

add_test(
        NAME TEST_MESSAGE_2_DECODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --decode_msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_MESSAGE_2_DECODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --decode_msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_MESSAGE_3_DECODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --decode_msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_MESSAGE_3_DECODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_internal --decode_msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_INITIATOR_MESSAGE_1_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_initiator --initiator-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_INITIATOR_MESSAGE_1_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_initiator --initiator-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_INITIATOR_MESSAGE_3_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_initiator --initiator-msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_INITIATOR_MESSAGE_3_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_initiator --initiator-msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_RESPONDER_MESSAGE_2_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_responder --responder test_vectors/vector1.json
)

add_test(
        NAME TEST_RESPONDER_MESSAGE_2_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_responder --responder test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hashing test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_HASHING_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hashing test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_ECDH_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --ecdh test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_ECDH_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --ecdh test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_HMAC_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hmac test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_HMAC_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --hmac test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2M_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2m test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2M_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2m test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_KDF_IV2M_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-iv2m test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_KDF_IV2M_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-iv2m test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2E_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2e test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_KDF_K2E_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --edhoc-kdf-k2e test_vectors/vector2.json
)

add_test(
        NAME TEST_CRYPTO_ED25519_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --ed25519 test_vectors/vector1.json
)

add_test(
        NAME TEST_CRYPTO_ED25519_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_crypto --ed25519 test_vectors/vector2.json
)

add_test(
        NAME TEST_COSE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_cose --x5t test_vectors/vector1.json
)

