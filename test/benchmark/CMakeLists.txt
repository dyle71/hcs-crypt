# ------------------------------------------------------------
# This file is the main CMakeLists of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020-2021 headcode.space e.U.  
# Oliver Maurhart <info@headcode.space>, https://www.headcode.space
# ------------------------------------------------------------

include_directories(${CMAKE_SOURCE_DIR}/include ${TEST_BASE_DIR} ${GTEST_INCLUDE_DIR} ${CMAKE_BINARY_DIR})
link_directories("${GTEST_LIBRARY_PATH};${GMOCK_LIBRARY_PATH}")
set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")

set(BENCHMARK_TEST_SRC
    test_copy.cpp
    test_nohash.cpp

    ltc/hash/test_ltc_md5.cpp
    ltc/hash/test_ltc_ripemd128.cpp
    ltc/hash/test_ltc_ripemd160.cpp
    ltc/hash/test_ltc_ripemd256.cpp
    ltc/hash/test_ltc_ripemd320.cpp
    ltc/hash/test_ltc_sha1.cpp
    ltc/hash/test_ltc_sha224.cpp
    ltc/hash/test_ltc_sha256.cpp
    ltc/hash/test_ltc_sha384.cpp
    ltc/hash/test_ltc_sha512.cpp
    ltc/hash/test_ltc_tiger192.cpp

    ltc/symmetric_cipher/test_ltc_aes_128_ecb.cpp
    ltc/symmetric_cipher/test_ltc_aes_192_ecb.cpp
    ltc/symmetric_cipher/test_ltc_aes_256_ecb.cpp
)


if (WITH_OPENSSL)
    set(BENCHMARK_TEST_OPENSSL_SRC

        openssl/hash/test_openssl_md5.cpp
        openssl/hash/test_openssl_ripemd160.cpp
        openssl/hash/test_openssl_sha1.cpp
        openssl/hash/test_openssl_sha224.cpp
        openssl/hash/test_openssl_sha256.cpp
        openssl/hash/test_openssl_sha384.cpp
        openssl/hash/test_openssl_sha512.cpp

        openssl/symmetric_cipher/test_openssl_aes_128_ecb.cpp
        openssl/symmetric_cipher/test_openssl_aes_192_ecb.cpp
        openssl/symmetric_cipher/test_openssl_aes_256_ecb.cpp
    )
endif()

add_executable(benchmark-tests ${BENCHMARK_TEST_SRC} ${BENCHMARK_TEST_OPENSSL_SRC})
target_link_libraries(benchmark-tests hcs-crypt gtest gtest_main gmock gmock_main ${CMAKE_REQUIRED_LIBRARIES})
gtest_add_tests(benchmark-tests "" AUTO)
