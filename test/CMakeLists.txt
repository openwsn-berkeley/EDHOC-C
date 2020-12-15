set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/test)

add_executable(edhoc_msg1 test_message1.c)
target_link_libraries(edhoc_msg1 PRIVATE edhoc-c::edhoc-c cn-cbor::cn-cbor)

add_test(NAME edhoc_msg1 COMMAND edhoc_msg1)
