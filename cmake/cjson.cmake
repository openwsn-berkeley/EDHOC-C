ExternalProject_Add(
        json-parser
        GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
        GIT_TAG master
        GIT_SHALLOW TRUE
        GIT_PROGRESS
        INSTALL_DIR ${CMAKE_BINARY_DIR}/3rdparty/cjson-build
        SOURCE_DIR ${CMAKE_BINARY_DIR}/3rdparty/cjson
        BINARY_DIR ${CMAKE_BINARY_DIR}/3rdparty/cjson
        UPDATE_COMMAND ""   # necessary to prevent full rebuild on incremental builds
        CMAKE_ARGS -DENABLE_CJSON_TEST=OFF -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/3rdparty/cjson-build
)

ExternalProject_Get_Property(json-parser install_dir)

add_library(cjson SHARED IMPORTED)
set_property(TARGET cjson PROPERTY IMPORTED_LOCATION ${install_dir}/lib/libcjson.so)

include_directories(${install_dir}/include)
