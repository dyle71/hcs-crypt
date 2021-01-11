# ------------------------------------------------------------
# This file is the main CMakeLists of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020 headcode.space
# https://www.headcode.space, <info@headcode.space>
# ------------------------------------------------------------

include_directories(${CMAKE_SOURCE_DIR}/include ${TEST_BASE_DIR} ${GTEST_INCLUDE_DIR} ${CMAKE_BINARY_DIR})
link_directories("${GTEST_LIBRARY_PATH};${GMOCK_LIBRARY_PATH}")
set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")

set(BENCHMARK_TEST_SRC
    test_copy.cpp
    test_nohash.cpp

    ltc/test_ltc_md5.cpp
    ltc/test_ltc_sha1.cpp
    ltc/test_ltc_sha224.cpp
    ltc/test_ltc_sha256.cpp
    ltc/test_ltc_sha384.cpp
    ltc/test_ltc_sha512.cpp
    ltc/test_ltc_tiger192.cpp
)


if (WITH_OPENSSL)
    set(BENCHMARK_TEST_OPENSSL_SRC
        openssl/test_openssl_md5.cpp
        openssl/test_openssl_sha1.cpp
        openssl/test_openssl_sha224.cpp
        openssl/test_openssl_sha256.cpp
        openssl/test_openssl_sha384.cpp
        openssl/test_openssl_sha512.cpp
    )
endif()

add_executable(benchmark-tests ${BENCHMARK_TEST_SRC} ${BENCHMARK_TEST_OPENSSL_SRC})
target_link_libraries(benchmark-tests hcs-crypt gtest gtest_main gmock gmock_main ${CMAKE_REQUIRED_LIBRARIES})
gtest_add_tests(benchmark-tests "" AUTO)
