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


TEST(SymmetricCipher_LTC_AES_ECB_128, creation) {

    auto algo = headcode::crypt::Factory::Create("ltc-aes-ecb-128");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_EQ(algo->Initialize(), 0);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "ltc-aes-ecb-128");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 16ul);
    EXPECT_EQ(description.block_size_outgoing_, 16ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_TRUE(description.initial_argument_.needed_);
}


TEST(SymmetricCipher_LTC_AES_ECB_128, simple) {

    auto algo = headcode::crypt::Factory::Create("ltc-aes-ecb-128");
    ASSERT_NE(algo.get(), nullptr);

    auto key = std::string{"supercalifragilisticexpialidocious"};
    ASSERT_EQ(algo->Initialize(key.c_str(), key.size()), 0);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    std::vector<std::byte> cipher;
    EXPECT_EQ(algo->Add(text, cipher), 0);

    // TODO: check cipher

    std::vector<std::byte> result;
    EXPECT_EQ(algo->Finalize(result), 0);
    EXPECT_TRUE(result.empty());
}


TEST(SymmetricCipher_LTC_AES_ECB_128, regular) {

    auto key = std::string{"supercalifragilisticexpialidocious"};

    // ---------- encrypt ----------

    auto algo_encrypt = headcode::crypt::Factory::Create("ltc-aes-ecb-128");
    ASSERT_NE(algo_encrypt.get(), nullptr);
    ASSERT_STREQ(algo_encrypt->GetDescription().name_.c_str(), "ltc-aes-ecb-128");

    ASSERT_EQ(algo_encrypt->Initialize(key.c_str(), key.size()), 0);

    EXPECT_TRUE(algo_encrypt->IsInitialized());
    EXPECT_FALSE(algo_encrypt->IsFinalized());

    std::vector<std::byte> cipher;
    EXPECT_EQ(algo_encrypt->Add(IPSUM_LOREM_TEXT, cipher), 0);

    // TODO: check cipher

    std::vector<std::byte> result;
    EXPECT_EQ(algo_encrypt->Finalize(result), 0);
    EXPECT_TRUE(result.empty());

    // ---------- decrypt ----------

    auto algo_decrypt = headcode::crypt::Factory::Create("ltc-aes-ecb-128");
    ASSERT_NE(algo_decrypt.get(), nullptr);
    ASSERT_STREQ(algo_decrypt->GetDescription().name_.c_str(), "ltc-aes-ecb-128");

    ASSERT_EQ(algo_decrypt->Initialize(key.c_str(), key.size()), 0);

    EXPECT_TRUE(algo_decrypt->IsInitialized());
    EXPECT_FALSE(algo_decrypt->IsFinalized());

    std::vector<std::byte> plain;
    EXPECT_EQ(algo_decrypt->Add(cipher, plain), 0);

    EXPECT_EQ(algo_decrypt->Finalize(result), 0);
    EXPECT_TRUE(result.empty());

    // ---------- plain == decrypt(encrypt(plain))? ----------

    // TODO
}
