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


TEST(SymmetricCipher_Copy, creation) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "copy");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 0ul);
    EXPECT_EQ(description.block_size_outgoing_, 0ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_TRUE(description.initialization_argument_.empty());
    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(SymmetricCipher_Copy, simple) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);

    auto text = std::string{"The quick brown fox jumps over the lazy dog"};
    std::vector<std::byte> cipher{text.size()};
    algo->Add(text, cipher);

    // COPY: copies from input to output

    EXPECT_EQ(std::memcmp(text.c_str(), cipher.data(), text.size()), 0);

    std::vector<std::byte> result;
    algo->Finalize(result);
    EXPECT_TRUE(result.empty());
    EXPECT_TRUE(algo->IsFinalized());
}


TEST(SymmetricCipher_Copy, regular) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "copy");
    EXPECT_EQ(algo->Initialize(), 0);
    EXPECT_TRUE(algo->IsInitialized());
    EXPECT_FALSE(algo->IsFinalized());

    // COPY: copies from input to output

    std::vector<std::byte> cipher{IPSUM_LOREM_TEXT.size()};
    algo->Add(IPSUM_LOREM_TEXT, cipher);
    EXPECT_EQ(std::memcmp(IPSUM_LOREM_TEXT.c_str(), cipher.data(), IPSUM_LOREM_TEXT.size()), 0);

    std::vector<std::byte> result;
    algo->Finalize(result);
    EXPECT_TRUE(result.empty());
    EXPECT_TRUE(algo->IsFinalized());
}


TEST(SymmetricCipher_Copy, empty) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "copy");
    EXPECT_EQ(algo->Initialize(), 0);

    std::vector<std::byte> plain;
    std::vector<std::byte> cipher;
    algo->Add(plain, cipher);
    EXPECT_EQ(plain.size(), 0ul);
    EXPECT_EQ(cipher.size(), 0ul);

    std::vector<std::byte> result;
    ASSERT_EQ(algo->Finalize(result), 0);
    EXPECT_TRUE(result.empty());
    EXPECT_TRUE(algo->IsFinalized());
}


TEST(SymmetricCipher_Copy, noinit) {

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetDescription().name_.c_str(), "copy");

    std::vector<std::byte> cipher{IPSUM_LOREM_TEXT.size()};
    algo->Add(IPSUM_LOREM_TEXT, cipher);
    EXPECT_EQ(std::memcmp(IPSUM_LOREM_TEXT.c_str(), cipher.data(), IPSUM_LOREM_TEXT.size()), 0);

    std::vector<std::byte> result;
    algo->Finalize(result);
    EXPECT_TRUE(result.empty());
    EXPECT_TRUE(algo->IsFinalized());
}
