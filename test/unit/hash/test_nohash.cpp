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


TEST(Hash_NoHash, creation) {

    auto algo = Factory::Create("nohash");
    ASSERT_NE(algo.get(), nullptr);

    EXPECT_STREQ(algo->GetName().c_str(), "nohash");
    EXPECT_EQ(algo->GetFamily(), Family::HASH);
    EXPECT_FALSE(algo->GetDescription().empty());
}
