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


TEST(SymmetricCipher_LTC_AES_128_ECB, creation) {

    auto algo = headcode::crypt::Factory::Create("ltc-aes-128-ecb encryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "ltc-aes-128-ecb encryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 16ul);
    EXPECT_EQ(description.block_size_outgoing_, 16ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_TRUE(description.initial_argument_.needed_);
}


TEST(SymmetricCipher_LTC_AES_128_ECB, single_block) {

    auto elgo_enc = headcode::crypt::Factory::Create("ltc-aes-128-ecb encryptor");
    ASSERT_NE(elgo_enc.get(), nullptr);

    auto key = std::string{
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"};

    // trim key to size
    key.resize(elgo_enc->GetDescription().initial_argument_.size_);
    ASSERT_EQ(elgo_enc->Initialize(key.c_str(), key.size()), 0);

    auto plain = elgo_enc->GrowToBlockSize("0123456789012345", elgo_enc->GetDescription().block_size_incoming_);
    plain.resize(elgo_enc->GetDescription().block_size_incoming_);
    std::vector<std::byte> cipher{plain.size()};
    EXPECT_EQ(elgo_enc->Add(plain, cipher), 0);

    // TODO: check cipher
    std::cout << key << std::endl;
    std::cout << headcode::mem::MemoryToHex(plain) << std::endl;
    std::cout << headcode::mem::MemoryToHex(cipher) << std::endl;

    std::vector<std::byte> result_enc;
    EXPECT_EQ(elgo_enc->Finalize(result_enc), 0);
    EXPECT_TRUE(result_enc.empty());

    auto algo_dec = headcode::crypt::Factory::Create("ltc-aes-128-ecb decryptor");
    ASSERT_NE(algo_dec.get(), nullptr);
    std::vector<std::byte> plain_decrypted{cipher.size()};
    EXPECT_EQ(algo_dec->Add(cipher, plain_decrypted), 0);
    std::cout << headcode::mem::MemoryToHex(plain_decrypted) << std::endl;
}


TEST(SymmetricCipher_LTC_AES_128_ECB, simple) {

    auto algo = headcode::crypt::Factory::Create("ltc-aes-128-ecb encryptor");
    ASSERT_NE(algo.get(), nullptr);

    auto key = std::string{
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"};

    // trim key to size
    key.resize(algo->GetDescription().initial_argument_.size_);
    ASSERT_EQ(algo->Initialize(key.c_str(), key.size()), 0);

    auto plain = algo->GrowToBlockSize("The quick brown fox jumps over the lazy dog.",
                                       algo->GetDescription().block_size_incoming_);
    std::vector<std::byte> cipher{plain.size()};
    EXPECT_EQ(algo->Add(plain, cipher), 0);

    // TODO: check cipher
    std::cout << key << std::endl;
    std::cout << headcode::mem::MemoryToHex(plain) << std::endl;
    std::cout << headcode::mem::MemoryToHex(cipher) << std::endl;

    std::vector<std::byte> result;
    EXPECT_EQ(algo->Finalize(result), 0);
    EXPECT_TRUE(result.empty());
}


TEST(SymmetricCipher_LTC_AES_128_ECB, regular) {

    // ---------- encrypt ----------

    auto algo_encrypt = headcode::crypt::Factory::Create("ltc-aes-128-ecb encryptor");
    ASSERT_NE(algo_encrypt.get(), nullptr);
    ASSERT_STREQ(algo_encrypt->GetDescription().name_.c_str(), "ltc-aes-128-ecb encryptor");

    auto key = std::string{
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"};

    auto key_enc = key;
    key_enc.resize(algo_encrypt->GetDescription().initial_argument_.size_);

    ASSERT_EQ(algo_encrypt->Initialize(key_enc.c_str(), key_enc.size()), 0);
    EXPECT_TRUE(algo_encrypt->IsInitialized());
    EXPECT_FALSE(algo_encrypt->IsFinalized());

    auto plain = algo_encrypt->GrowToBlockSize(IPSUM_LOREM_TEXT, algo_encrypt->GetDescription().block_size_incoming_);
    std::vector<std::byte> cipher{plain.size()};
    EXPECT_EQ(algo_encrypt->Add(plain, cipher), 0);

    // TODO: check cipher
    std::cout << headcode::mem::MemoryToHex(cipher) << std::endl;

    std::vector<std::byte> result;
    EXPECT_EQ(algo_encrypt->Finalize(result), 0);
    EXPECT_TRUE(result.empty());

    // ---------- decrypt ----------

    auto algo_decrypt = headcode::crypt::Factory::Create("ltc-aes-128-ecb decryptor");
    ASSERT_NE(algo_decrypt.get(), nullptr);
    ASSERT_STREQ(algo_decrypt->GetDescription().name_.c_str(), "ltc-aes-128-ecb decryptor");

    auto key_dec = key;
    key_dec.resize(algo_encrypt->GetDescription().initial_argument_.size_);
    ASSERT_EQ(algo_decrypt->Initialize(key_dec.c_str(), key_dec.size()), 0);

    EXPECT_TRUE(algo_decrypt->IsInitialized());
    EXPECT_FALSE(algo_decrypt->IsFinalized());

    std::vector<std::byte> plain_decrypted{cipher.size()};
    EXPECT_EQ(algo_decrypt->Add(cipher, plain_decrypted), 0);
    std::cout << headcode::mem::MemoryToHex(plain_decrypted) << std::endl;

    EXPECT_EQ(algo_decrypt->Finalize(result), 0);
    EXPECT_TRUE(result.empty());

    // ---------- plain == decrypt(encrypt(plain))? ----------

    // TODO
}
