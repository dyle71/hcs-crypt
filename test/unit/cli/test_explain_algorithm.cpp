/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */


#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include "shared/split_lines.hpp"

#include "../../../src/bin/explain_algorithm.hpp"


TEST(Crypt_explain_algorithm, unknown) {

    std::stringstream ss;
    ExplainAlgorithm(ss, "<unknown");
    auto lines = Split(ss.str());
    ASSERT_EQ(lines.size(), 1ul);
    EXPECT_STREQ(lines.at(0).c_str(), "Unknown algorithm with this name.");
}


/**
 * @param   Parameterized test fixture class.
 */
class TestPaddingCryptExplain : public testing::TestWithParam<::testing::tuple<std::string>> {

protected:
    /**
     * @brief   Setup the paramterized tests.
     */
    void SetUp() override {
    }

    /**
     * @brief   Wind down the paramterized tests.
     */
    void TearDown() override {
    }
};


TEST_P(TestPaddingCryptExplain, algorithms_paramterized) {

    std::string algorithm = ::testing::get<0>(GetParam());

    std::stringstream ss;
    ExplainAlgorithm(ss, algorithm);
    auto lines = Split(ss.str());
    ASSERT_GT(lines.size(), 1ul);
    std::string expected_name = std::string{"Name: "} + algorithm;
    EXPECT_STREQ(lines.at(0).c_str(), expected_name.c_str());
}


INSTANTIATE_TEST_SUITE_P(Crypt_explain_algorithms,
                         TestPaddingCryptExplain,
                         ::testing::Values("openssl-aes-192-ecb-encryptor",
                                           "openssl-aes-256-ecb-encryptor",
                                           "openssl-aes-128-ecb-encryptor",
                                           "openssl-aes-192-ecb-decryptor",
                                           "openssl-aes-256-ecb-decryptor",
                                           "openssl-aes-128-ecb-decryptor",
                                           "openssl-aes-192-cbc-encryptor",
                                           "openssl-aes-256-cbc-encryptor",
                                           "openssl-aes-192-cbc-decryptor",
                                           "openssl-aes-128-cbc-encryptor",
                                           "openssl-aes-256-cbc-decryptor",
                                           "openssl-aes-128-cbc-decryptor",
                                           "ltc-aes-256-ecb-encryptor",
                                           "ltc-aes-192-ecb-decryptor",
                                           "ltc-aes-256-ecb-decryptor",
                                           "ltc-aes-128-ecb-encryptor",
                                           "ltc-aes-128-ecb-decryptor",
                                           "ltc-aes-192-ecb-encryptor",
                                           "ltc-aes-256-cbc-decryptor",
                                           "ltc-aes-192-cbc-encryptor",
                                           "ltc-aes-128-cbc-decryptor",
                                           "ltc-aes-192-cbc-decryptor",
                                           "ltc-aes-128-cbc-encryptor",
                                           "ltc-aes-256-cbc-encryptor",
                                           "copy",
                                           "openssl-md5",
                                           "openssl-sha1",
                                           "openssl-ripemd160",
                                           "openssl-sha384",
                                           "openssl-sha512",
                                           "openssl-sha256",
                                           "openssl-sha224",
                                           "ltc-ripemd320",
                                           "ltc-sha224",
                                           "ltc-tiger192",
                                           "ltc-sha512",
                                           "ltc-ripemd160",
                                           "ltc-ripemd128",
                                           "ltc-md5",
                                           "ltc-sha256",
                                           "ltc-sha384",
                                           "ltc-ripemd256",
                                           "ltc-sha1",
                                           "nohash"));
