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
    EXPECT_FALSE(description.description_.empty());
    EXPECT_EQ(description.block_size_incoming_, 16ul);
    EXPECT_EQ(description.block_size_outgoing_, 16ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_TRUE(description.initial_argument_.needed_);
}


TEST(SymmetricCipher_LTC_AES_ECB_128, simple) {

    auto algo = headcode::crypt::Factory::Create("ltc-aes-ecb-128");
    ASSERT_NE(algo.get(), nullptr);

    auto key = std::string{"supercalifragilisticexpialidocious"};
    ASSERT_EQ(algo->Initialize(key.c_str(), key.size()), 0);

    auto text = std::string{"The quick brown fox jumps over the lazy dog."};
    EXPECT_EQ(algo->Add(text), 0);

    std::vector<std::byte> cipher;
    EXPECT_EQ(algo->Finalize(cipher), 0);
    EXPECT_EQ(cipher.size(), text.size());

    auto expected = std::string{"e4d909c290d0fb1ca068ffaddf22cbd0"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(cipher).c_str(), expected.c_str());
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

    algo_encrypt->Add(IPSUM_LOREM_TEXT);

    std::vector<std::byte> cipher;
    EXPECT_EQ(algo_encrypt->Finalize(cipher), 0);
    EXPECT_EQ(cipher.size(), IPSUM_LOREM_TEXT.size());

    // ---------- decrypt ----------

    auto algo_decrypt = headcode::crypt::Factory::Create("ltc-aes-ecb-128");
    ASSERT_NE(algo_decrypt.get(), nullptr);
    ASSERT_STREQ(algo_decrypt->GetDescription().name_.c_str(), "ltc-aes-ecb-128");

    ASSERT_EQ(algo_decrypt->Initialize(key.c_str(), key.size()), 0);

    EXPECT_TRUE(algo_decrypt->IsInitialized());
    EXPECT_FALSE(algo_decrypt->IsFinalized());

    algo_decrypt->Add(cipher);

    std::vector<std::byte> plain;
    EXPECT_EQ(algo_decrypt->Finalize(plain), 0);
    EXPECT_EQ(plain.size(), IPSUM_LOREM_TEXT.size());
    auto plain_text = std::string{reinterpret_cast<char const *>(plain.data())};
    EXPECT_STREQ(plain_text.c_str(), IPSUM_LOREM_TEXT.c_str());
}
