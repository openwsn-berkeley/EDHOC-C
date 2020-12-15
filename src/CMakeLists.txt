if (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_COMPILER_ID MATCHES "Clang")
    message(STATUS "adding GCC/Clang options ")
    add_definitions(-Wall -Wextra -pedantic)
    if (EDHOC_C_FATAL_WARNINGS)
        add_definitions(-Werror)
    endif ()
    if (EDHOC_C_OPTIMIZE)
        add_definitions(-Os)
        add_definitions(-DNDEBUG)
    endif ()
elseif (MSVC)
    add_definitions(/W4)
    if (EDHOC_C_FATAL_WARNINGS)
        add_definitions(/WX)
    endif ()
    if (EDHOC_C_OPTIMIZE)
        add_definitions(-DNDEBUG)
    endif ()
else ()
    message(FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}")
endif ()

add_library(${PROJECT_NAME})

set(edhoc_sources
        ${PROJECT_SOURCE_DIR}/include/edhoc/edhoc.h
        message1.c
        )

target_sources(${PROJECT_NAME} PRIVATE ${edhoc_sources})

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ../src)
target_link_libraries(${PROJECT_NAME} PRIVATE cn-cbor::cn-cbor)

add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

###############################################################################
#INSTALL LIBRARY
###############################################################################

include(GNUInstallDirs)
