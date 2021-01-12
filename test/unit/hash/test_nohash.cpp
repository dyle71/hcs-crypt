/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>

#include "shared/ipsum_lorem.hpp"


TEST(Hash_NoHash, creation) {

    auto algo = headcode::crypt::Factory::Create("nohash");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "nohash");
    EXPECT_EQ(description.family_, headcode::crypt::Family::HASH);
    EXPECT_FALSE(description.description_.empty());
    EXPECT_EQ(description.block_size_incoming_, 0ul);
    EXPECT_EQ(description.block_size_outgoing_, 0ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_FALSE(description.initial_argument_.needed_);
}


TEST(Hash_NoHash, simple) {

    auto algo = headcode::crypt::Factory::Create("nohash");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};

    EXPECT_EQ(algo->Add(text), 0);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);

    EXPECT_EQ(hash.size(), 0ul);
}


TEST(Hash_NoHash, regular) {

    auto algo = headcode::crypt::Factory::Create("nohash");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "nohash");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    // NOHASH: always returns empty value.

    EXPECT_EQ(algo->Add(IPSUM_LOREM_TEXT), 0);
    std::vector<std::byte> hash;
    ASSERT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), 0ul);
    EXPECT_TRUE(algo->IsFinalized());
}


TEST(Hash_NoHash, empty) {

    auto algo = headcode::crypt::Factory::Create("nohash");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "nohash");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> hash;
    ASSERT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), 0ul);
}


TEST(Hash_NoHash, noinit) {

    auto algo = headcode::crypt::Factory::Create("nohash");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "nohash");

    // NOHASH: always returns empty value.

    EXPECT_EQ(algo->Add(IPSUM_LOREM_TEXT), 0);
    std::vector<std::byte> hash;
    ASSERT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), 0ul);

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}
