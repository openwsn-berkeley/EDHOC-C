# unit tests for EDHOC

add_compile_definitions(${EDHOC_CRYPTO_BACKEND})

# create all executables
add_executable(test_format test_format.c util.c util.h json.h json.c)
target_link_libraries(test_format PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_format PRIVATE cjson)
target_include_directories(test_format PRIVATE ../src)

add_executable(test_process test_process.c util.c util.h json.h json.c)
target_link_libraries(test_process PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_process PRIVATE cjson)
target_include_directories(test_process PRIVATE ../src)

add_executable(test_crypto test_crypto.c util.c util.h json.h json.c)
target_link_libraries(test_crypto PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_crypto PRIVATE cjson)
target_include_directories(test_crypto PRIVATE ../src)

add_executable(test_cbor test_cbor.c util.c util.h json.h json.c)
target_link_libraries(test_cbor PRIVATE edhoc-c::edhoc-c)
target_link_libraries(test_cbor PRIVATE cjson)
target_include_directories(test_cbor PRIVATE ../src)


add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode_msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode_msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_ENCODE_3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode_msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode_msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode_msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_1_DECODE_3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode_msg1 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode_msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode_msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_ENCODE_3
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode_msg2 test_vectors/vector3.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode_msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_2_DECODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode_msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_DATA_2_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-data2 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_DATA_2_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-data2 test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_INFO_K2M_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-k2m test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_INFO_K2M_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-k2m test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_INFO_IV2M_ENCODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-iv2m test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_INFO_IV2M_ENCODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --encode-info-iv2m test_vectors/vector2.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode_msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_FORMAT_MESSAGE_3_DECODE_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_format --decode_msg3 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg1 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_1_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg1 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg2 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_2_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg2 test_vectors/vector2.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_1
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg3 test_vectors/vector1.json
)

add_test(
        NAME TEST_PROCESS_MESSAGE_3_2
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND test_process --create-msg3 test_vectors/vector2.json
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
