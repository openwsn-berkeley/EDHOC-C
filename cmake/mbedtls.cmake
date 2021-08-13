if (BUILD_SHARED_LIBS)
    set(SHARED On)
    set(STATIC Off)
else ()
    set(SHARED Off)
    set(STATIC On)
endif ()

ExternalProject_Add(
        mbedtls-backend
        GIT_REPOSITORY https://github.com/ARMmbed/mbedtls.git
        GIT_TAG 1905a244886c00f2fea12b8589a934e759d617af
        GIT_PROGRESS TRUE
        INSTALL_DIR ${CMAKE_BINARY_DIR}/3rdparty/mbedtls-build
        SOURCE_DIR ${CMAKE_BINARY_DIR}/3rdparty/mbedtls
        BINARY_DIR ${CMAKE_BINARY_DIR}/3rdparty/mbedtls
        UPDATE_COMMAND ""
        CONFIGURE_COMMAND
        COMMAND cmake ${CMAKE_BINARY_DIR}/3rdparty/mbedtls
        -DCMAKE_BUILD_TYPE=Debug
        -DENABLE_TESTING:BOOL=Off
        -DENABLE_PROGRAMS:BOOL=Off
        -DUSE_SHARED_MBEDTLS_LIBRARY:BOOL=${SHARED}
        -DUSE_STATIC_MBEDTLS_LIBRARY:BOOL=${STATIC}
        -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/3rdparty/mbedtls-build
        -DCMAKE_INSTALL_RPATH:PATH=${CMAKE_BINARY_DIR}/3rdparty/mbedtls-build/lib
        BUILD_COMMAND cmake --build .)

ExternalProject_Get_Property(mbedtls-backend install_dir)

add_library(mbedx509 SHARED IMPORTED)
set_property(TARGET mbedx509 PROPERTY IMPORTED_LOCATION ${install_dir}/lib/libmbedx509.so)

add_dependencies(edhoc-c mbedtls-backend)

target_include_directories(${PROJECT_NAME} PUBLIC ${install_dir}/include)

target_link_libraries(${PROJECT_NAME} PRIVATE mbedx509)