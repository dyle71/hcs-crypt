/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>


TEST(Factory, unknown_algorithm) {
    auto algo = headcode::crypt::Factory::Create("UNKNOWN-ALGORITHM");
    ASSERT_EQ(algo.get(), nullptr);
}


TEST(Factory, list_crypher_symmetric) {

    auto algorithms = headcode::crypt::Factory::GetAlgorithmDescriptions();

    std::uint64_t symmetric_cyphers_count{0};
    for (auto const & [name, description] : algorithms) {
        if (description.family_ == headcode::crypt::Family::CYPHER_SYMMETRIC) {
            symmetric_cyphers_count++;
        }
    }

    EXPECT_EQ(symmetric_cyphers_count, 1ul);
    EXPECT_NE(algorithms.find("copy"), algorithms.end());
}


TEST(Factory, list_hashes) {

    auto algorithms = headcode::crypt::Factory::GetAlgorithmDescriptions();

    std::uint64_t hashes_count{0};
    for (auto const & [name, description] : algorithms) {
        if (description.family_ == headcode::crypt::Family::HASH) {
            hashes_count++;
        }
    }

    std::uint64_t expected_count = 8ul;
#ifdef OPENSSL
    expected_count += 6ul;
#endif

    EXPECT_EQ(hashes_count, expected_count);

    EXPECT_NE(algorithms.find("nohash"), algorithms.end());

    EXPECT_NE(algorithms.find("ltc-md5"), algorithms.end());
    EXPECT_NE(algorithms.find("ltc-sha1"), algorithms.end());
    EXPECT_NE(algorithms.find("ltc-sha224"), algorithms.end());
    EXPECT_NE(algorithms.find("ltc-sha256"), algorithms.end());
    EXPECT_NE(algorithms.find("ltc-sha384"), algorithms.end());
    EXPECT_NE(algorithms.find("ltc-sha512"), algorithms.end());
    EXPECT_NE(algorithms.find("ltc-tiger192"), algorithms.end());

#ifdef OPENSSL

    EXPECT_NE(algorithms.find("openssl-md5"), algorithms.end());
    EXPECT_NE(algorithms.find("openssl-sha1"), algorithms.end());
    EXPECT_NE(algorithms.find("openssl-sha224"), algorithms.end());
    EXPECT_NE(algorithms.find("openssl-sha256"), algorithms.end());
    EXPECT_NE(algorithms.find("openssl-sha384"), algorithms.end());
    EXPECT_NE(algorithms.find("openssl-sha512"), algorithms.end());

#endif
}


TEST(Factory, list_unknown) {

    // every algorithm must belong to a known family
    auto algorithms = headcode::crypt::Factory::GetAlgorithmDescriptions();
    auto some_unknown = std::any_of(algorithms.begin(), algorithms.end(), [](auto const & p) {
        return p.second.family_ == headcode::crypt::Family::UNKNOWN;
    });

    EXPECT_FALSE(some_unknown);
}
