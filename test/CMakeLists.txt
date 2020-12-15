set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/test)

add_executable(edhoc_test test.c)
target_link_libraries(edhoc_test PRIVATE edhoc-c::edhoc-c cn-cbor::cn-cbor)

add_test(NAME edhoc_test COMMAND edhoc_test)
