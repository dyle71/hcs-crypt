# ------------------------------------------------------------
# This file is the main CMakeLists of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020-2021 headcode.space e.U.  
# Oliver Maurhart <info@headcode.space>, https://www.headcode.space
# ------------------------------------------------------------

# ------------------------------------------------------------
# tl;dr - How to create a package - copy-paste to a shell:
#
# 1. git clone --recurse-submodules https://gitlab.com/headcode.space/crypt.git
# 2. cd crypt
# 3. mkdir build
# 4. cd buld
# 5.1) cmake -D CMAKE_BUILD_TYPE=Release -D CPACK_GENERATOR=DEB ..        # for DEB packages
# - xor -
# 5.2) cmake -D CMAKE_BUILD_TYPE=Release -D CPACK_GENERATOR=RPM ..        # for RPM packages
# 6. CORES=`grep 'cpu cores' /proc/cpuinfo | awk '{ print $4 }' | head -n 1` make -j $CORES
# 7. make package
# ------------------------------------------------------------

project(hcs-crypt C CXX)
cmake_minimum_required(VERSION 3.13.4)

cmake_policy(SET CMP0075 NEW)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake;${HCS_CMAKE}")

if (CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Debug")
endif ()
message(STATUS "CMake build type: ${CMAKE_BUILD_TYPE}")

ENABLE_TESTING()


# ------------------------------------------------------------
# Project Version

set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "1")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")


# ------------------------------------------------------------
# prime CMake includes

include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckIncludeFiles)
include(CheckLibraryExists)

include(run-gcovr)


# ------------------------------------------------------------
# set global compiler flags

add_definitions(-DVERSION_MAJOR=${VERSION_MAJOR})
add_definitions(-DVERSION_MINOR=${VERSION_MINOR})
add_definitions(-DVERSION_PATCH=${VERSION_PATCH})
add_definitions(-DVERSION=\"${VERSION}\")
add_definitions(-D_GNU_SOURCE)
add_definitions(-D_DEFAULT_SOURCE)


# ---- fix C++ standard used ----

set(CMAKE_CXX_STANDARD 17)
if ((CMAKE_COMPILER_IS_GNUCC) OR (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang"))
    set(COMPILER_WARNINGS "-Wall -Wextra -pedantic -pedantic-errors")
    set(COMPILER_FLAGS_DEBUG "-O0 -g -ggdb3 -fno-builtin -fPIC")
    set(COMPILER_FLAGS_RELEASE "-O3 -Werror -Werror -fno-builtin -fPIC")
    set(LINKER_FLAGS "-rdynamic")
endif ()

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    message(STATUS "Turning on compiler command export for CLang: ${CMAKE_BINARY_DIR}/compile_commands.json")
endif ()

# ---- callgrind integration ----

option(CALLGRIND_ENABLED "enable callgrind" off)
if (CALLGRIND_ENABLED)
    message(STATUS "callgrind enabled")
    message(WARNING "callgrind enabled: make package will create defective package!")
    set(VALGRIND_NEEDED "1")
    set(CALLGRIND_OPTIONS "")
else ()
    message(STATUS "callgrind disabled")
endif ()

# ---- final compiler settings ----

set(CMAKE_C_FLAGS_DEBUG "${COMPILER_WARNINGS} ${COMPILER_FLAGS_DEBUG} ${COMPILER_FLAGS_PROFILING}")
set(CMAKE_CXX_FLAGS_DEBUG "${COMPILER_WARNINGS} ${COMPILER_FLAGS_DEBUG} ${COMPILER_FLAGS_PROFILING}")
set(CMAKE_C_FLAGS_RELEASE "${COMPILER_WARNINGS} ${COMPILER_FLAGS_RELEASE} ${COMPILER_FLAGS_PROFILING}")
set(CMAKE_CXX_FLAGS_RELEASE "${COMPILER_WARNINGS} ${COMPILER_FLAGS_RELEASE} ${COMPILER_FLAGS_PROFILING}")
set(CMAKE_EXE_LINKER_FLAGS "${LINKER_FLAGS} ${LINKER_FLAGS_PROFILING}")


# ------------------------------------------------------------
# libtommath
#
# Download https://github.com/libtom/libtommath as
#
#   $ git submodule add https://github.com/libtom/libtommath 3rd/libtommath

if (NOT EXISTS "${CMAKE_SOURCE_DIR}/3rd/libtommath/makefile.unix")
    message(FATAL_ERROR "The git submodule for libtommath has not been downloaded!")
endif ()
message(STATUS "Found libtommath")

execute_process(COMMAND make -f makefile.unix libtommath.a
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/3rd/libtommath"
)

include_directories(${CMAKE_SOURCE_DIR}/3rd/libtommath)


# ------------------------------------------------------------
# libtomcrypt... as default working horse
#
# Download https://github.com/libtom/libtomcrypt.git as
#
#   $ git submodule add https://github.com/libtom/libtomcrypt.git 3rd/libtomcrypt

if (NOT EXISTS "${CMAKE_SOURCE_DIR}/3rd/libtomcrypt/makefile.unix")
    message(FATAL_ERROR "The git submodule for libtomcrypt has not been downloaded!")
endif ()
message(STATUS "Found libtomcrypt")

execute_process(COMMAND make -f makefile.unix libtomcrypt.a
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/3rd/libtomcrypt"
)

include_directories(${CMAKE_SOURCE_DIR}/3rd/libtomcrypt/src/headers)
link_libraries(${CMAKE_SOURCE_DIR}/3rd/libtomcrypt/libtomcrypt.a)


# ------------------------------------------------------------
# OpenSSL as alternative provider: https://www.openssl.org/
#

option(WITH_OPENSSL "Add OpenSSL as algorithm provider." on)
if (WITH_OPENSSL)

    message(STATUS "Building hcs-crypto with OpenSSL.")
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)

    include_directories(${OPENSSL_INCLUDE_DIR})
    link_libraries(${OPENSSL_CRYPTO_LIBRARY})
    add_compile_definitions(OPENSSL)

endif ()


# ------------------------------------------------------------
# headcode/benchmark as submodule

include(hcs-benchmark)
message(STATUS "HCS_BENCHMARK_INCLUDE_DIR: ${HCS_BENCHMARK_INCLUDE_DIR}")
include_directories(${HCS_BENCHMARK_INCLUDE_DIR})


# ------------------------------------------------------------
# headcode/mem as submodule

include(hcs-mem)
message(STATUS "HCS_MEM_INCLUDE_DIR: ${HCS_MEM_INCLUDE_DIR}")
include_directories(${HCS_MEM_INCLUDE_DIR})


# ------------------------------------------------------------
# headcode/logger as submodule

include(hcs-logger)
message(STATUS "HCS_LOGGER_INCLUDE_DIR: ${HCS_LOGGER_INCLUDE_DIR}")
include_directories(${HCS_LOGGER_INCLUDE_DIR})
if ("${HCS_LOGGER_LIB}" STREQUAL "")
    message(FATAL_ERROR "Could not build or locate hcs-logger library.")
endif ()
set(CMAKE_REQUIRED_LIBRARIES "${HCS_LOGGER_LIB};${CMAKE_REQUIRED_LIBRARIES}")


# ------------------------------------------------------------
# Doxygen

find_package(Doxygen)
if (DOXYGEN_FOUND STREQUAL "NO")
    message(FATAL_ERROR "Doxygen not found. Please get a copy http://www.doxygen.org")
endif ()

configure_file(${CMAKE_SOURCE_DIR}/Doxyfile ${CMAKE_BINARY_DIR}/Doxyfile)
add_custom_target(doxygen ALL
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        COMMENT "Doxygen running ...")
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES api-doc)

add_custom_target(doc)
add_dependencies(doc doxygen)
install(DIRECTORY ${CMAKE_BINARY_DIR}/html
        DESTINATION share/doc/hcs-crypt-${VERSION_MAJOR}.${VERSION_MINOR}
        COMPONENT documentation
)


# ------------------------------------------------------------ 
# Workload

add_subdirectory(src)

if (BUILD_TESTING)
    message(STATUS "Building tests")
    add_subdirectory(test)
else()
    message(STATUS "Building without tests")
    message(STATUS "To enable tests invoke cmake with \"-D BUILD_TESTING=on\" arguments.")
endif ()


# ------------------------------------------------------------
# Installing stuff

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/headcode/crypt DESTINATION include/headcode COMPONENT header)


# ---- CPack global definitions ----

set(CPACK_PACKAGE_NAME "headcode-crypt")
set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})

set(CPACK_PACKAGE_DESCRIPTION "Tiny and easy to use crypto library in C++.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "This is a tiny and easy to use library to run crypto algroithms in C++.")
set(CPACK_PACKAGE_CONTACT "Oliver Maurhart <oliver.maurhart@headcode.space>")
set(CPACK_PACKAGE_VENDOR "headcode.space")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}-${CMAKE_SYSTEM_PROCESSOR}")

set(CPACK_SOURCE_IGNORE_FILES "./build/*;/.git/;/.idea/;/.scannerwork/;/.sonar/;/sonar-project.properties")
set(CPACK_SOURCE_GENERATOR "TGZ")

if ("${CPACK_GENERATOR}" STREQUAL "DEB")

    if (WITH_OPENSSL)
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl")
    else()
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
    endif()

    set(PACKAGE_DEB_CONTROL_DIR "tools/package/deb")
    include(cmake/deb-package.cmake)

    # only works inside a GitLab CI/CD runner
    set(GITLAB_PACKAGE_BASE_URL "https://gitlab.com/api/v4/projects/22433969/packages/generic/hcs-crypt")
    set(PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}.deb")
    set(PACKAGE_FILE "${CMAKE_BINARY_DIR}/${PACKAGE_FILE_NAME}")
    include(gitlab-package-push)

endif()

if ("${CPACK_GENERATOR}" STREQUAL "RPM")

    if (WITH_OPENSSL)
        set(CPACK_RPM_PACKAGE_REQUIRES "openssl")
    else()
        set(CPACK_RPM_PACKAGE_REQUIRES "")
    endif()

    set(PACKAGE_RPM_CONTROL_DIR "tools/package/rpm")
    include(cmake/rpm-package.cmake)

    # only works inside a GitLab CI/CD runner
    set(GITLAB_PACKAGE_BASE_URL "https://gitlab.com/api/v4/projects/22433969/packages/generic/hcs-crypt")
    set(PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}.rpm")
    set(PACKAGE_FILE "${CMAKE_BINARY_DIR}/${PACKAGE_FILE_NAME}")
    include(gitlab-package-push)

endif()

include(CPack)
