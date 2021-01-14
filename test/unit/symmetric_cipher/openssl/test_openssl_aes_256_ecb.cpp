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


TEST(SymmetricCipher_OpenSSL_AES_256_ECB, encryptor_creation) {

    auto algo = headcode::crypt::Factory::Create("openssl-aes-256-ecb encryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "openssl-aes-256-ecb encryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 32ul);
    EXPECT_EQ(description.block_size_outgoing_, 32ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_EQ(description.initialization_argument_.size(), 1);
    ASSERT_NE(description.initialization_argument_.find("key"), description.finalization_argument_.end());
    auto argument_description_key = description.initialization_argument_.at("key");
    EXPECT_EQ(argument_description_key.size_, 32ul);
    EXPECT_FALSE(argument_description_key.optional_);
    EXPECT_FALSE(argument_description_key.description_.empty());
    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(SymmetricCipher_OpenSSL_AES_256_ECB, decryptor_creation) {

    auto algo = headcode::crypt::Factory::Create("openssl-aes-256-ecb decryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "openssl-aes-256-ecb decryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 32ul);
    EXPECT_EQ(description.block_size_outgoing_, 32ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_EQ(description.initialization_argument_.size(), 1);
    ASSERT_NE(description.initialization_argument_.find("key"), description.finalization_argument_.end());
    auto argument_description_key = description.initialization_argument_.at("key");
    EXPECT_EQ(argument_description_key.size_, 32ul);
    EXPECT_FALSE(argument_description_key.optional_);
    EXPECT_FALSE(argument_description_key.description_.empty());
    EXPECT_TRUE(description.finalization_argument_.empty());
}


TEST(SymmetricCipher_OpenSSL_AES_256_ECB, single_block) {

    auto algo_enc = headcode::crypt::Factory::Create("openssl-aes-256-ecb encryptor");
    ASSERT_NE(algo_enc.get(), nullptr);

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
    key.resize(algo_enc->GetDescription().initial_argument_.size_);
    ASSERT_EQ(algo_enc->Initialize(key.c_str(), key.size()), 0);

    // --------- encrypt ---------

    plain.resize(algo_enc->GetDescription().block_size_incoming_);
    std::vector<std::byte> cipher{plain.size()};
    EXPECT_EQ(algo_enc->Add(plain, cipher), 0);

    std::vector<std::byte> result_enc;
    EXPECT_EQ(algo_enc->Finalize(result_enc), 0);
    EXPECT_TRUE(result_enc.empty());

    // --------- decrypt ---------

    auto algo_dec = headcode::crypt::Factory::Create("openssl-aes-256-ecb decryptor");
    ASSERT_NE(algo_dec.get(), nullptr);
    ASSERT_EQ(algo_dec->Initialize(key.c_str(), key.size()), 0);

    std::vector<std::byte> plain_decrypted{cipher.size()};
    EXPECT_EQ(algo_dec->Add(cipher, plain_decrypted), 0);

    // --------- check ---------

    ASSERT_EQ(plain.size(), cipher.size());
    ASSERT_EQ(plain_decrypted.size(), cipher.size());
    EXPECT_NE(std::memcmp(plain.data(), cipher.data(), plain.size()), 0);
    EXPECT_NE(std::memcmp(plain_decrypted.data(), cipher.data(), plain_decrypted.size()), 0);
    EXPECT_EQ(std::memcmp(plain.data(), plain_decrypted.data(), plain.size()), 0);
    EXPECT_STREQ(headcode::mem::MemoryToHex(plain).c_str(),
                 "3031323334353637383930313233343500000000000000000000000000000000");
    EXPECT_STREQ(headcode::mem::MemoryToHex(cipher).c_str(),
                 "9730932c94d67db58f575cbdfb905f0599df3909cb1dbdb867a464e3017c66a4");
}


TEST(SymmetricCipher_OpenSSL_AES_256_ECB, regular) {

    auto algo_enc = headcode::crypt::Factory::Create("openssl-aes-256-ecb encryptor");
    ASSERT_NE(algo_enc.get(), nullptr);

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
    key.resize(algo_enc->GetDescription().initial_argument_.size_);
    ASSERT_EQ(algo_enc->Initialize(key.c_str(), key.size()), 0);

    // --------- encrypt ---------

    auto plain = algo_enc->GrowToBlockSize(IPSUM_LOREM_TEXT, algo_enc->GetDescription().block_size_incoming_);
    std::vector<std::byte> cipher{plain.size()};
    EXPECT_EQ(algo_enc->Add(plain, cipher), 0);

    std::vector<std::byte> result_enc;
    EXPECT_EQ(algo_enc->Finalize(result_enc), 0);
    EXPECT_TRUE(result_enc.empty());

    // --------- decrypt ---------

    auto algo_dec = headcode::crypt::Factory::Create("openssl-aes-256-ecb decryptor");
    ASSERT_NE(algo_dec.get(), nullptr);
    ASSERT_EQ(algo_dec->Initialize(key.c_str(), key.size()), 0);

    std::vector<std::byte> plain_decrypted{cipher.size()};
    EXPECT_EQ(algo_dec->Add(cipher, plain_decrypted), 0);

    // --------- check ---------

    ASSERT_EQ(plain.size(), cipher.size());
    ASSERT_EQ(plain_decrypted.size(), cipher.size());
    EXPECT_NE(std::memcmp(plain.data(), cipher.data(), plain.size()), 0);
    EXPECT_NE(std::memcmp(plain_decrypted.data(), cipher.data(), plain_decrypted.size()), 0);
    EXPECT_EQ(std::memcmp(plain.data(), plain_decrypted.data(), plain.size()), 0);
}
