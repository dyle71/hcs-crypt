/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>
#include <headcode/mem/mem.hpp>

#include "shared/ipsum_lorem.hpp"


TEST(Hash_LTCMD5, creation) {

    auto algo = headcode::crypt::Factory::Create("ltc-md5");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "ltc-md5");
    EXPECT_EQ(description.family_, headcode::crypt::Family::HASH);
    EXPECT_FALSE(description.description_.empty());
    EXPECT_EQ(description.block_size_incoming_, 64ul);
    EXPECT_EQ(description.block_size_outgoing_, 16ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_FALSE(description.initial_argument_.needed_);
}


TEST(Hash_LTCMD5, simple) {

    auto algo = headcode::crypt::Factory::Create("ltc-md5");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    EXPECT_EQ(algo->Add(text), 0);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);

    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{"e4d909c290d0fb1ca068ffaddf22cbd0"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_LTCMD5, regular) {

    auto algo = headcode::crypt::Factory::Create("ltc-md5");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-md5");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{"c9f9e773953864f55f1681d00783b10f"};
    auto result = headcode::mem::MemoryToHex(hash);
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_TRUE(algo->IsFinalized());
}


TEST(Hash_LTCMD5, empty) {

    auto algo = headcode::crypt::Factory::Create("ltc-md5");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-md5");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{"d41d8cd98f00b204e9800998ecf8427e"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_LTCMD5, noinit) {

    auto algo = headcode::crypt::Factory::Create("ltc-md5");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-md5");

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{"c9f9e773953864f55f1681d00783b10f"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}
