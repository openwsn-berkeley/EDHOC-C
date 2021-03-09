ExternalProject_Add(
        hacl-backend
        GIT_REPOSITORY https://github.com/project-everest/hacl-star.git
        GIT_TAG master
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
        INSTALL_DIR ${CMAKE_BINARY_DIR}/3rdparty/hacl-build
        SOURCE_DIR ${CMAKE_BINARY_DIR}/3rdparty/hacl
        BINARY_DIR ${CMAKE_BINARY_DIR}/3rdparty/hacl/dist/gcc-compatible
        UPDATE_COMMAND ""   # necessary to prevent full rebuild on incremental builds
        CONFIGURE_COMMAND ./configure
        BUILD_COMMAND make
        INSTALL_COMMAND
        COMMAND cmake -E make_directory ${CMAKE_BINARY_DIR}/3rdparty/hacl-build/lib
        COMMAND cmake -E make_directory ${CMAKE_BINARY_DIR}/3rdparty/hacl-build/include
        COMMAND cmake -E copy ${CMAKE_BINARY_DIR}/3rdparty/hacl/dist/gcc-compatible/libevercrypt.so ${CMAKE_BINARY_DIR}/3rdparty/hacl-build/lib
        COMMAND cmake -E copy_directory ${CMAKE_BINARY_DIR}/3rdparty/hacl/dist/gcc-compatible ${CMAKE_BINARY_DIR}/3rdparty/nanocbor-build/include
)

ExternalProject_Get_Property(hacl-backend install_dir)

add_library(hacl SHARED IMPORTED)
set_property(TARGET hacl PROPERTY IMPORTED_LOCATION ${install_dir}/lib/libevercrypt.so)

add_dependencies(edhoc-c hacl-backend)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${install_dir}/include
        ${CMAKE_BINARY_DIR}/3rdparty/hacl/dist/kremlin/include
        ${CMAKE_BINARY_DIR}/3rdparty/hacl/dist/kremlin/kremlib/dist/minimal)

target_link_libraries(${PROJECT_NAME} PRIVATE hacl)

