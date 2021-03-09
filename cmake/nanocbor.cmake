ExternalProject_Add(
        nanocbor-backend
        GIT_REPOSITORY https://github.com/bergzand/NanoCBOR.git
        GIT_TAG ded3a901c890e605bce56ee5b9729c23710e23ed
        GIT_PROGRESS TRUE
        INSTALL_DIR ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build
        SOURCE_DIR ${CMAKE_BINARY_DIR}/3rdparty/nanocbor
        BINARY_DIR ${CMAKE_BINARY_DIR}/3rdparty/nanocbor
        UPDATE_COMMAND ""   # necessary to prevent full rebuild on incremental builds
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        INSTALL_COMMAND
        COMMAND cmake -E make_directory ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/lib
        COMMAND cmake -E make_directory ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/include
        COMMAND cmake -E copy ${CMAKE_BINARY_DIR}/3rdparty/nanocbor/bin/nanocbor.so ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/lib
        COMMAND cmake -E rename  ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/lib/nanocbor.so ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/lib/libnanocbor.so
        COMMAND cmake -E copy_directory ${CMAKE_BINARY_DIR}/3rdparty/nanocbor/include ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/include)


ExternalProject_Get_Property(nanocbor-backend install_dir)

add_library(nanocbor SHARED IMPORTED)
set_property(TARGET nanocbor PROPERTY IMPORTED_LOCATION ${install_dir}/lib/libnanocbor.so)

add_dependencies(edhoc-c nanocbor-backend)

target_include_directories(${PROJECT_NAME} PRIVATE ${install_dir}/include)

target_link_libraries(${PROJECT_NAME} PRIVATE nanocbor)
