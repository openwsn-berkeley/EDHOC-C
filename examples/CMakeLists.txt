link_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/lib)
include_directories(${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build/include)

link_directories(${CMAKE_BINARY_DIR}/3rdparty/mbedtls-build/lib)
include_directories(${CMAKE_BINARY_DIR}/3rdparty/mbedtls-build/include)

add_executable(tcp-resp-sign-x509 tcp/resp-sign-x509.c util.c)
target_include_directories(tcp-resp-sign-x509 PRIVATE . ..)
target_link_libraries(tcp-resp-sign-x509 PRIVATE edhoc-c::edhoc-c wolfssl mbedx509)
add_dependencies(tcp-resp-sign-x509 edhoc-c::edhoc-c wolfssl-backend mbedtls-backend)

add_executable(tcp-init-sign-x509 tcp/init-sign-x509.c util.c)
target_include_directories(tcp-init-sign-x509 PRIVATE . ..)
target_link_libraries(tcp-init-sign-x509 PRIVATE edhoc-c::edhoc-c wolfssl mbedx509)
add_dependencies(tcp-init-sign-x509 edhoc-c::edhoc-c wolfssl-backend mbedtls-backend)

# add_executable(coap_responder coap/responder.c coap/nanocoap.c)
# target_link_libraries(coap_responder PRIVATE edhoc-c::edhoc-c)
