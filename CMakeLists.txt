cmake_minimum_required(VERSION 3.11)

set(VERSION_MAJOR 0 CACHE STRING "Project major version number")
set(VERSION_MINOR "1" CACHE STRING "Project minor version number")
set(VERSION_PATCH "0" CACHE STRING "Project patch version number")
set(EDHOC_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

project("edhoc-c" LANGUAGES C VERSION "${EDHOC_VERSION}")

set(CMAKE_C_STANDARD 99)

add_subdirectory(src)

###############################################################################
# OPTIONS
###############################################################################

option(EDHOC_C_USE_CONTEXT "Use context pointer for COSE functions" OFF)
option(EDHOC_C_BUILD_TESTS "build tests" ON)


option(BUILD_SHARED_LIBS "Build Shared Libraries" OFF)

# Set the output of the libraries and executables.
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})

set(dist_dir ${CMAKE_BINARY_DIR}/dist)
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX}/bin)
set(libdir ${CMAKE_INSTALL_PREFIX}/lib)
set(includedir ${CMAKE_INSTALL_PREFIX}/include)

###############################################################################
# DEPENDENCIES
###############################################################################

if (EDHOC_C_USE_FIND_PACKAGE)
    find_package(cn-cbor)
else ()
    include(FetchContent)

    FetchContent_Declare(CN_CBOR GIT_REPOSITORY https://github.com/jimsch/cn-cbor.git GIT_TAG master)
    FetchContent_GetProperties(CN_CBOR)
    string(TOLOWER "CN_CBOR" lcName)

    if (NOT ${lcName}_POPULATED)
        FetchContent_Populate(CN_CBOR)
        set(CN_CBOR_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
        set(CN_CBOR_COVERALLS OFF CACHE BOOL "" FORCE)
        set(CN_CBOR_USE_CONTEXT ${EDHOC_C_USE_CONTEXT} CACHE BOOL "" FORCE)
        set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS} CACHE BOOL "" FORCE)
        set(CN_CBOR_BUILD_DOCS OFF CACHE BOOL "" FORCE)
        set(CN_CBOR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        add_subdirectory(${${lcName}_SOURCE_DIR} ${${lcName}_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif ()
endif ()

if (BUILD_SHARED_LIBS)
    set(BUILD_STATIC_LIBS OFF)
else ()
    set(BUILD_STATIC_LIBS ON)
endif ()

###############################################################################
# ADD TESTS
###############################################################################

if (EDHOC_C_BUILD_TESTS)
    enable_testing()
    # include(CTest)
    add_subdirectory(test)
endif ()

###############################################################################
# PRINT CONFIG
###############################################################################

message(STATUS "EDHOC_C_BUILD_TESTS:..............${EDHOC_C_BUILD_TESTS}")
message(STATUS "CN_CBOR_SOURCE_DIR:...............${${lcName}_SOURCE_DIR}")
message(STATUS "CN_CBOR_BINARY_DIR:...............${${lcName}_BINARY_DIR}")