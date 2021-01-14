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


TEST(Hash_LTCSHA512, creation) {

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "ltc-sha512");
    EXPECT_EQ(description.family_, headcode::crypt::Family::HASH);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 128ul);
    EXPECT_EQ(description.block_size_outgoing_, 0ul);
    EXPECT_EQ(description.result_size_, 64ul);

    EXPECT_TRUE(description.initialization_argument_.empty());
    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(Hash_LTCSHA512, simple) {

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    EXPECT_EQ(algo->Add(text), 0);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "b8b31b9af416031e07c293bf1716e383"
            "df4e5c57670d593636a1bf7a88ac8f66"
            "abf4f64cedd7b0c2db069d3ccf9cf58c"
            "975c51df84c9dc3bfe58e15fa24be14c"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_LTCSHA512, regular) {

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha512");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "3a25bf52049f192e80b7197afba62ea6"
            "0c03792725497b01ae459e8d868997b9"
            "e4f6697cf0d106c910958770217d449d"
            "1995b4a842ad1a613ef2636ffba675b5"};
    auto result = headcode::mem::MemoryToHex(hash);
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_TRUE(algo->IsFinalized());
}


TEST(Hash_LTCSHA512, empty) {

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha512");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "cf83e1357eefb8bdf1542850d66d8007"
            "d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f"
            "63b931bd47417a81a538327af927da3e"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_LTCSHA512, noinit) {

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha512");

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "3a25bf52049f192e80b7197afba62ea6"
            "0c03792725497b01ae459e8d868997b9"
            "e4f6697cf0d106c910958770217d449d"
            "1995b4a842ad1a613ef2636ffba675b5"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}
