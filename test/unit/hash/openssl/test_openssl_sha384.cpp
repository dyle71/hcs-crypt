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
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 128ul);
    EXPECT_EQ(description.block_size_outgoing_, 0ul);
    EXPECT_EQ(description.result_size_, 48ul);

    EXPECT_TRUE(description.initialization_argument_.empty());
    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(Hash_OPENSSLSHA384, simple) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    EXPECT_EQ(algo->Add(text), 0);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "8549bef9c0fb9cde8edcc87b8fba76ff"
            "5b7acd3a9ef8291bcbd9bcfa092b2f5b"
            "6c8b5bfe94071af0c64288b9d1dbf127"};
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
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "3684988b349f5116652c9eacce66ff91"
            "b57d7f92e8d9b40a4ae8f8ac8db96076"
            "e0560db656924f8c187cd7e0a15c035d"};
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
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "38b060a751ac96384cd9327eb1b1e36a"
            "21fdb71114be07434c0cc7bf63f6e1da"
            "274edebfe76f65fbd51ad2f14898b95b"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_OPENSSLSHA384, noinit) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha384");

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{
            "3684988b349f5116652c9eacce66ff91"
            "b57d7f92e8d9b40a4ae8f8ac8db96076"
            "e0560db656924f8c187cd7e0a15c035d"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}
