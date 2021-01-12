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


TEST(Hash_OPENSSLSHA384, creation) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "openssl-sha384");
    EXPECT_EQ(description.family_, headcode::crypt::Family::HASH);
    EXPECT_FALSE(description.description_.empty());
    EXPECT_EQ(description.block_size_incoming_, 128ul);
    EXPECT_EQ(description.block_size_outgoing_, 48ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_FALSE(description.initial_argument_.needed_);
}


TEST(Hash_OPENSSLSHA384, simple) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    EXPECT_EQ(algo->Add(text), 0);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{
            "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6"
            "c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_OPENSSLSHA384, regular) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha384");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{
            "37fb5f101139c74c4bb2518108c6bf4c0b28e848db65b8ea"
            "d94245818c3265ab4c385add4a1c071468453ab66a07fff1"};
    auto result = headcode::mem::MemoryToHex(hash);
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_TRUE(algo->IsFinalized());
}


TEST(Hash_OPENSSLSHA384, empty) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha384");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
            "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_OPENSSLSHA384, noinit) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha384");

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().block_size_outgoing_);

    auto expected = std::string{
            "37fb5f101139c74c4bb2518108c6bf4c0b28e848db65b8ea"
            "d94245818c3265ab4c385add4a1c071468453ab66a07fff1"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}
