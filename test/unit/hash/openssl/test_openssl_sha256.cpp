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


TEST(Hash_OPENSSLSHA256, creation) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha256");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "openssl-sha256");
    EXPECT_EQ(description.family_, headcode::crypt::Family::HASH);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 64ul);
    EXPECT_EQ(description.block_size_outgoing_, 0ul);
    EXPECT_EQ(description.result_size_, 32ul);

    EXPECT_TRUE(description.initialization_argument_.empty());
    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(Hash_OPENSSLSHA256, simple) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha256");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    EXPECT_EQ(algo->Add(text), 0);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"a83e558088b4bc88bf3bbdaf6d0bb98ef2291288c12f1f5289d6f9f82d03f4ec"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_OPENSSLSHA256, regular) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha256");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha256");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"8372e8dc1413d0636d8db66e5f8f4f885e703e67c736aa80a881ac400dc8613b"};
    auto result = headcode::mem::MemoryToHex(hash);
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_TRUE(algo->IsFinalized());
}


TEST(Hash_OPENSSLSHA256, empty) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha256");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha256");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());
}


TEST(Hash_OPENSSLSHA256, noinit) {

    auto algo = headcode::crypt::Factory::Create("openssl-sha256");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha256");

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> hash;
    EXPECT_EQ(algo->Finalize(hash), 0);
    EXPECT_EQ(hash.size(), algo->GetDescription().result_size_);

    auto expected = std::string{"8372e8dc1413d0636d8db66e5f8f4f885e703e67c736aa80a881ac400dc8613b"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(hash).c_str(), expected.c_str());

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}
