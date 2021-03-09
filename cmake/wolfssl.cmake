ExternalProject_Add(
        wolfssl-backend
        GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
        GIT_TAG master
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
        INSTALL_DIR ${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build
        SOURCE_DIR ${CMAKE_BINARY_DIR}/3rdparty/wolfssl
        BINARY_DIR ${CMAKE_BINARY_DIR}/3rdparty/wolfssl
        UPDATE_COMMAND ""   # necessary to prevent full rebuild on incremental builds
        CONFIGURE_COMMAND
        COMMAND ./autogen.sh
        COMMAND ./configure --prefix=${CMAKE_BINARY_DIR}/3rdparty/wolfssl-build
                            --enable-aesccm
                            --enable-hkdf
                            --enable-curve25519
                            --enable-ed25519
                            --enable-cryptonly
                            --disable-filesystem
                            --disable-crypttests
        BUILD_COMMAND make install
        INSTALL_COMMAND "")

ExternalProject_Get_Property(wolfssl-backend install_dir)

add_library(wolfssl SHARED IMPORTED)
set_property(TARGET wolfssl PROPERTY IMPORTED_LOCATION ${install_dir}/lib/libwolfssl.so)

add_dependencies(edhoc-c wolfssl-backend)

target_include_directories(${PROJECT_NAME} PRIVATE ${install_dir}/include)

target_link_libraries(${PROJECT_NAME} PRIVATE wolfssl)

