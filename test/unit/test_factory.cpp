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

    auto known_symmetric_cyphers =
            headcode::crypt::Factory::GetAlgorithmDescriptions(headcode::crypt::Family::CYPHER_SYMMETRIC);
    EXPECT_EQ(known_symmetric_cyphers.size(), 1ul);

    EXPECT_NE(known_symmetric_cyphers.find("copy"), known_symmetric_cyphers.end());
}


TEST(Factory, list_hashes) {

    auto known_hashes = headcode::crypt::Factory::GetAlgorithmDescriptions(headcode::crypt::Family::HASH);

    auto all_known_hashes = 3ul;
#ifndef OPENSSL
    all_known_hashes -= 1;
#endif

    EXPECT_EQ(known_hashes.size(), all_known_hashes);
    EXPECT_NE(known_hashes.find("nohash"), known_hashes.end());
}


TEST(Factory, list_unknown) {
    auto known_unknown = headcode::crypt::Factory::GetAlgorithmDescriptions(headcode::crypt::Family::UNKNOWN);
    EXPECT_TRUE(known_unknown.empty());
}
