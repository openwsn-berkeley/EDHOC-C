if (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(STATUS "Adding GCC/Clang options ")
    add_definitions(-Wall -Wextra -pedantic)
    if (EDHOC_FATAL_WARNINGS)
        add_definitions(-Werror)
    endif ()
elseif (MSVC)
    add_definitions(/W4)
    if (EDHOC_FATAL_WARNINGS)
        add_definitions(/WX)
    endif ()
else ()
    message(FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}")
endif ()

###############################################################################
# COMPILE DEFINITIONS
###############################################################################

add_compile_definitions(${EDHOC_CRYPTO_BACKEND})
add_compile_definitions(${EDHOC_CBOR_BACKEND})
add_compile_definitions(${EDHOC_X509_BACKEND})

add_library(${PROJECT_NAME})

set(edhoc_sources
        ${PROJECT_SOURCE_DIR}/src/process.c
        ${PROJECT_SOURCE_DIR}/src/credentials.c
        ${PROJECT_SOURCE_DIR}/src/cipher_suites.c
        ${PROJECT_SOURCE_DIR}/src/cose.c
        ${PROJECT_SOURCE_DIR}/src/format.c
        ${PROJECT_SOURCE_DIR}/src/edhoc.c
        ${PROJECT_SOURCE_DIR}/src/cbor/nanocbor.c
        ${PROJECT_SOURCE_DIR}/src/cbor/empty.c
        ${PROJECT_SOURCE_DIR}/src/crypto/wolfssl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/hacl.c
        ${PROJECT_SOURCE_DIR}/src/crypto/empty.c
        ${PROJECT_SOURCE_DIR}/src/crypto/aes128.c
        ${PROJECT_SOURCE_DIR}/src/crypto/ccm.c)

target_sources(${PROJECT_NAME} PRIVATE ${edhoc_sources})

target_include_directories(${PROJECT_NAME}
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        PRIVATE
        ${PROJECT_SOURCE_DIR}/src)

if ("${EDHOC_X509_BACKEND}" STREQUAL "MBEDTLS_X509")
    include(mbedtls)
endif ()

if ("${EDHOC_CBOR_BACKEND}" STREQUAL "NANOCBOR")
    include(nanocbor)
endif ()

if ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "WOLFSSL")
    include(wolfssl)
elseif ("${EDHOC_CRYPTO_BACKEND}" STREQUAL "HACL")
    include(hacl)
endif ()

add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "edhoc")
