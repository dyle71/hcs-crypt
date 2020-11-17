/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>

using namespace headcode::crypt;


TEST(Factory, unknown_algorithm) {
    auto algo = Factory::Create("UNKNOWN-ALGORITHM");
    ASSERT_EQ(algo.get(), nullptr);
}


TEST(Factory, list_crypher_symmetric) {

    auto known_symmetric_cyphers = Factory::GetAlgorithmNames(Family::CYPHER_SYMMETRIC);
    EXPECT_EQ(known_symmetric_cyphers.size(), 1ul);

    EXPECT_NE(known_symmetric_cyphers.find("copy"), known_symmetric_cyphers.end());
}


TEST(Factory, list_hashes) {

    auto known_hashes = Factory::GetAlgorithmNames(Family::HASH);
    EXPECT_EQ(known_hashes.size(), 1ul);

    EXPECT_NE(known_hashes.find("nohash"), known_hashes.end());
}


TEST(Factory, list_unknown) {
    auto known_unknown = Factory::GetAlgorithmNames(Family::UNKNOWN);
    EXPECT_TRUE(known_unknown.empty());
}
