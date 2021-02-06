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


TEST(Hash_LTCRIPEMD160, creation) {

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd160");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "ltc-ripemd160");
    EXPECT_EQ(description.family_, headcode::crypt::Family::kHash);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 64ul);
    EXPECT_EQ(description.block_size_outgoing_, 0ul);
    EXPECT_EQ(description.result_size_, 20ul);

    EXPECT_TRUE(description.initialization_argument_.empty());
    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(Hash_LTCRIPEMD160, simple) {

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd160");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    EXPECT_EQ(algo->Add(text), 0);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"18b06b8dba026202bc46712c2534db4840634a52"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_LTCRIPEMD160, regular) {

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd160");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd160");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    algo->Add(kIpsumLoremText);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"3726da4a1e0d315569b3b1977bcfa2cac022f0c0"};
    auto result = headcode::mem::MemoryToHex(hash);
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_TRUE(algo->IsFinalized());
}


TEST(Hash_LTCRIPEMD160, empty) {

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd160");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd160");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"9c1185a5c5e9fc54612808977ee8f548b2258d31"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_LTCRIPEMD160, noinit) {

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd160");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd160");

    algo->Add(kIpsumLoremText);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"3726da4a1e0d315569b3b1977bcfa2cac022f0c0"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}
