/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <headcode/mem/mem.hpp>
#include <headcode/crypt/crypt.hpp>

#include "shared/ipsum_lorem.hpp"


TEST(SymmetricCipher_LTC_AES_192_CBC, encryptor_creation) {

    auto algo = headcode::crypt::Factory::Create("ltc-aes-192-cbc-encryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "ltc-aes-192-cbc-encryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::kSymmetricCipher);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 16ul);
    EXPECT_EQ(description.block_size_outgoing_, 16ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_EQ(description.initialization_argument_.size(), 2ul);
    ASSERT_NE(description.initialization_argument_.find("key"), description.finalization_argument_.end());
    auto argument_description_key = description.initialization_argument_.at("key");
    EXPECT_EQ(argument_description_key.size_, 24ul);
    EXPECT_FALSE(argument_description_key.optional_);
    EXPECT_FALSE(argument_description_key.description_.empty());

    ASSERT_NE(description.initialization_argument_.find("iv"), description.finalization_argument_.end());
    auto argument_description_iv = description.initialization_argument_.at("iv");
    EXPECT_EQ(argument_description_iv.size_, 16ul);
    EXPECT_FALSE(argument_description_iv.optional_);
    EXPECT_FALSE(argument_description_iv.description_.empty());

    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(SymmetricCipher_LTC_AES_192_CBC, decryptor_creation) {

    auto algo = headcode::crypt::Factory::Create("ltc-aes-192-cbc-decryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "ltc-aes-192-cbc-decryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::kSymmetricCipher);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 16ul);
    EXPECT_EQ(description.block_size_outgoing_, 16ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_EQ(description.initialization_argument_.size(), 2ul);
    ASSERT_NE(description.initialization_argument_.find("key"), description.finalization_argument_.end());
    auto argument_description_key = description.initialization_argument_.at("key");
    EXPECT_EQ(argument_description_key.size_, 24ul);
    EXPECT_FALSE(argument_description_key.optional_);
    EXPECT_FALSE(argument_description_key.description_.empty());

    ASSERT_NE(description.initialization_argument_.find("iv"), description.finalization_argument_.end());
    auto argument_description_iv = description.initialization_argument_.at("iv");
    EXPECT_EQ(argument_description_iv.size_, 16ul);
    EXPECT_FALSE(argument_description_iv.optional_);
    EXPECT_FALSE(argument_description_iv.description_.empty());

    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(SymmetricCipher_LTC_AES_192_CBC, single_block) {

    auto key = headcode::mem::StringToMemory(
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious");

    auto iv = headcode::mem::StringToMemory("This is an initialization vector.");

    auto algo_enc = headcode::crypt::Factory::Create("ltc-aes-192-cbc-encryptor");
    ASSERT_NE(algo_enc.get(), nullptr);
    ASSERT_NE(algo_enc->GetDescription().initialization_argument_.find("key"),
              algo_enc->GetDescription().finalization_argument_.end());
    ASSERT_NE(algo_enc->GetDescription().initialization_argument_.find("iv"),
              algo_enc->GetDescription().finalization_argument_.end());

    auto key_enc = key;
    key_enc.resize(algo_enc->GetDescription().initialization_argument_.at("key").size_);
    auto iv_enc = iv;
    iv_enc.resize(algo_enc->GetDescription().initialization_argument_.at("iv").size_);
    ASSERT_EQ(algo_enc->Initialize({{"key", key_enc}, {"iv", iv_enc}}), 0);

    // --------- encrypt ---------

    auto plain = std::vector<std::byte>{algo_enc->GetDescription().block_size_incoming_};
    std::memcpy(plain.data(), kIpsumLoremText.c_str(), plain.size());

    std::vector<std::byte> cipher;
    EXPECT_EQ(algo_enc->Add(plain, cipher), 0);
    EXPECT_EQ(plain.size(), cipher.size());

    std::vector<std::byte> result_enc;
    EXPECT_EQ(algo_enc->Finalize(result_enc), 0);
    EXPECT_TRUE(result_enc.empty());

    // --------- decrypt ---------

    auto algo_dec = headcode::crypt::Factory::Create("ltc-aes-192-cbc-decryptor");
    ASSERT_NE(algo_dec.get(), nullptr);
    ASSERT_NE(algo_dec->GetDescription().initialization_argument_.find("key"),
              algo_dec->GetDescription().finalization_argument_.end());
    ASSERT_NE(algo_dec->GetDescription().initialization_argument_.find("iv"),
              algo_dec->GetDescription().finalization_argument_.end());

    auto key_dec = key;
    key_dec.resize(algo_dec->GetDescription().initialization_argument_.at("key").size_);
    auto iv_dec = iv;
    iv_dec.resize(algo_dec->GetDescription().initialization_argument_.at("iv").size_);
    ASSERT_EQ(algo_dec->Initialize({{"key", key_dec}, {"iv", iv_dec}}), 0);

    std::vector<std::byte> plain_decrypted;
    EXPECT_EQ(algo_dec->Add(cipher, plain_decrypted), 0);

    // --------- check ---------

    ASSERT_EQ(plain.size(), cipher.size());
    ASSERT_EQ(plain_decrypted.size(), cipher.size());
    EXPECT_NE(std::memcmp(plain.data(), cipher.data(), plain.size()), 0);
    EXPECT_NE(std::memcmp(plain_decrypted.data(), cipher.data(), plain_decrypted.size()), 0);
    EXPECT_EQ(std::memcmp(plain.data(), plain_decrypted.data(), plain.size()), 0);

    EXPECT_STREQ(headcode::mem::MemoryToHex(plain).c_str(), "0a4c6f72656d20697073756d20646f6c");
    EXPECT_STREQ(headcode::mem::MemoryToHex(cipher).c_str(), "812289b07ff9540e59f44b7161bcdb5d");
}


TEST(SymmetricCipher_LTC_AES_192_CBC, regular) {

    auto key = headcode::mem::StringToMemory(
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious");

    auto iv = headcode::mem::StringToMemory("This is an initialization vector.");

    auto algo_enc = headcode::crypt::Factory::Create("ltc-aes-192-cbc-encryptor");
    ASSERT_NE(algo_enc.get(), nullptr);
    ASSERT_NE(algo_enc->GetDescription().initialization_argument_.find("key"),
              algo_enc->GetDescription().finalization_argument_.end());
    ASSERT_NE(algo_enc->GetDescription().initialization_argument_.find("iv"),
              algo_enc->GetDescription().finalization_argument_.end());

    auto key_enc = key;
    key_enc.resize(algo_enc->GetDescription().initialization_argument_.at("key").size_);
    auto iv_enc = iv;
    iv_enc.resize(algo_enc->GetDescription().initialization_argument_.at("iv").size_);
    ASSERT_EQ(algo_enc->Initialize({{"key", key_enc}, {"iv", iv_enc}}), 0);

    // --------- encrypt ---------

    auto plain = headcode::mem::StringToMemory(kIpsumLoremText);

    std::vector<std::byte> cipher;
    EXPECT_EQ(algo_enc->Add(plain, cipher), 0);
    EXPECT_LE(plain.size(), cipher.size());
    EXPECT_EQ(cipher.size() % algo_enc->GetDescription().block_size_outgoing_, 0ul);

    std::vector<std::byte> result_enc;
    EXPECT_EQ(algo_enc->Finalize(result_enc), 0);
    EXPECT_TRUE(result_enc.empty());

    // --------- decrypt ---------

    auto algo_dec = headcode::crypt::Factory::Create("ltc-aes-192-cbc-decryptor");
    ASSERT_NE(algo_dec.get(), nullptr);
    ASSERT_NE(algo_dec->GetDescription().initialization_argument_.find("key"),
              algo_dec->GetDescription().finalization_argument_.end());
    ASSERT_NE(algo_dec->GetDescription().initialization_argument_.find("iv"),
              algo_dec->GetDescription().finalization_argument_.end());

    auto key_dec = key;
    key_dec.resize(algo_dec->GetDescription().initialization_argument_.at("key").size_);
    auto iv_dec = iv;
    iv_dec.resize(algo_dec->GetDescription().initialization_argument_.at("iv").size_);
    ASSERT_EQ(algo_dec->Initialize({{"key", key_dec}, {"iv", iv_dec}}), 0);

    std::vector<std::byte> plain_decrypted;
    EXPECT_EQ(algo_dec->Add(cipher, plain_decrypted), 0);
    EXPECT_EQ(plain_decrypted.size(), cipher.size());
    EXPECT_EQ(plain_decrypted.size() % algo_enc->GetDescription().block_size_outgoing_, 0ul);

    // --------- check ---------

    // convert back to text and cut off any added padding in the decrypted text
    auto plain_txt = std::string{reinterpret_cast<char const *>(plain.data())};
    auto plain_decrypted_txt = std::string{reinterpret_cast<char const *>(plain_decrypted.data())};
    plain_decrypted_txt.resize(plain_txt.size());

    EXPECT_NE(std::memcmp(plain_decrypted.data(), cipher.data(), plain_decrypted.size()), 0);
    EXPECT_STREQ(plain_txt.c_str(), plain_decrypted_txt.c_str());
}
