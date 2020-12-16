/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>
#include <headcode/mem/mem.hpp>

#include "shared/ipsum_lorem.hpp"


TEST(CryptSymmetric_Copy, creation) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "copy");
    EXPECT_EQ(description.family_, headcode::crypt::Family::CYPHER_SYMMETRIC);
    EXPECT_FALSE(description.description_.empty());

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_FALSE(description.initial_argument_.needed_);
}


TEST(CryptSymmetric_Copy, simple) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog"};
    algo->Add(text);
    std::vector<std::byte> cypher;
    algo->Finalize(cypher);

    auto expected = headcode::mem::MemoryToHex(text.data(), text.size());
    auto result = headcode::mem::MemoryToHex(cypher);
    EXPECT_STREQ(expected.c_str(), result.c_str());
}


TEST(CryptSymmetric_Copy, regular) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "copy");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    // COPY: copies from input to output

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> cypher;
    ASSERT_EQ(algo->Finalize(cypher), 0);
    auto expected = headcode::mem::MemoryToHex(IPSUM_LOREM_TEXT.data(), IPSUM_LOREM_TEXT.size());
    auto result = headcode::mem::MemoryToHex(cypher);

    EXPECT_STREQ(expected.c_str(), result.c_str());
    EXPECT_TRUE(algo->IsFinalized());
}


TEST(CryptSymmetric_Copy, empty) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "copy");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> cypher;
    ASSERT_EQ(algo->Finalize(cypher), 0);
    EXPECT_EQ(cypher.size(), 0ul);
}


TEST(CryptSymmetric_Copy, noinit) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "copy");

    // COPY: copies from input to output

    algo->Add(IPSUM_LOREM_TEXT);
    std::vector<std::byte> cypher;
    ASSERT_EQ(algo->Finalize(cypher), 0);
    auto expected = headcode::mem::MemoryToHex(IPSUM_LOREM_TEXT.data(), IPSUM_LOREM_TEXT.size());
    auto result = headcode::mem::MemoryToHex(cypher);

    EXPECT_STREQ(expected.c_str(), result.c_str());

    EXPECT_FALSE(algo->IsInitialized());
    EXPECT_TRUE(algo->IsFinalized());
}


