# ------------------------------------------------------------
# This file is the main CMakeLists of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020 headcode.space
# https://www.headcode.space, <info@headcode.space>
# ------------------------------------------------------------

include_directories(${CMAKE_SOURCE_DIR}/include;${TEST_BASE_DIR};${GTEST_INCLUDE_DIR};${CMAKE_BINARY_DIR})
link_directories("${GTEST_LIBRARY_PATH};${GMOCK_LIBRARY_PATH}")
set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")

set(UNIT_TEST_SRC

    test_factory.cpp
    test_family.cpp
    test_version.cpp

    ${CMAKE_SOURCE_DIR}/src/bin/cli.cpp
    cli/test_cli.cpp

    cypher_symmetric/test_copy.cpp

    hash/test_nohash.cpp
    hash/ltc/test_ltc_md5.cpp
    hash/ltc/test_ltc_sha1.cpp
    hash/ltc/test_ltc_sha224.cpp
    hash/ltc/test_ltc_sha256.cpp
    hash/ltc/test_ltc_sha384.cpp
    hash/ltc/test_ltc_sha512.cpp
)

if (WITH_OPENSSL)
    set(UNIT_TEST_OPENSSL_SRC
        hash/openssl/test_openssl_md5.cpp
    )
endif ()


add_executable(unit-tests ${UNIT_TEST_SRC} ${UNIT_TEST_OPENSSL_SRC})
target_link_libraries(unit-tests hcs-crypt gtest gtest_main gmock gmock_main ${CMAKE_REQUIRED_LIBRARIES})
gtest_add_tests(unit-tests "" AUTO)
