add_compile_definitions(${EDHOC_CRYPTO_BACKEND})
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

add_executable(tcp-resp-sign-x509 tcp/resp-sign-x509.c util.c)
target_include_directories(tcp-resp-sign-x509 PRIVATE . ..)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(tcp-resp-sign-x509 PRIVATE edhoc-c::edhoc-c wolfssl mbedx509)
    add_dependencies(tcp-resp-sign-x509 edhoc-c::edhoc-c wolfssl-backend mbedtls-backend)
else ()
    target_link_libraries(tcp-resp-sign-x509 PRIVATE edhoc-c::edhoc-c evercrypt mbedx509)
    add_dependencies(tcp-resp-sign-x509 edhoc-c::edhoc-c hacl-backend mbedtls-backend)
endif ()

add_executable(tcp-init-sign-x509 tcp/init-sign-x509.c util.c)
target_include_directories(tcp-init-sign-x509 PRIVATE . ..)

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    target_link_libraries(tcp-init-sign-x509 PRIVATE edhoc-c::edhoc-c wolfssl mbedx509)
    add_dependencies(tcp-init-sign-x509 edhoc-c::edhoc-c wolfssl-backend mbedtls-backend)
else ()
    target_link_libraries(tcp-init-sign-x509 PRIVATE edhoc-c::edhoc-c evercrypt mbedx509)
    add_dependencies(tcp-init-sign-x509 edhoc-c::edhoc-c hacl-backend mbedtls-backend)
endif ()

# add_executable(coap_responder coap/responder.c coap/nanocoap.c)
# target_link_libraries(coap_responder PRIVATE edhoc-c::edhoc-c)
