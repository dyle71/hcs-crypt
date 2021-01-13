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


TEST(SymmetricCipher_OpenSSL_AES_192_ECB, encryptor_creation) {

    auto algo = headcode::crypt::Factory::Create("openssl-aes-192-ecb encryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "openssl-aes-192-ecb encryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 24ul);
    EXPECT_EQ(description.block_size_outgoing_, 24ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_TRUE(description.initial_argument_.needed_);
}


TEST(SymmetricCipher_OpenSSL_AES_192_ECB, decryptor_creation) {

    auto algo = headcode::crypt::Factory::Create("openssl-aes-192-ecb decryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "openssl-aes-192-ecb decryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 24ul);
    EXPECT_EQ(description.block_size_outgoing_, 24ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_TRUE(description.initial_argument_.needed_);
}


TEST(SymmetricCipher_OpenSSL_AES_192_ECB, single_block) {

    auto algo_enc = headcode::crypt::Factory::Create("openssl-aes-192-ecb encryptor");
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

    auto plain = algo_enc->GrowToBlockSize("0123456789012345", algo_enc->GetDescription().block_size_incoming_);
    plain.resize(algo_enc->GetDescription().block_size_incoming_);
    std::vector<std::byte> cipher{plain.size()};
    EXPECT_EQ(algo_enc->Add(plain, cipher), 0);

    std::vector<std::byte> result_enc;
    EXPECT_EQ(algo_enc->Finalize(result_enc), 0);
    EXPECT_TRUE(result_enc.empty());

    // --------- decrypt ---------

    auto algo_dec = headcode::crypt::Factory::Create("openssl-aes-192-ecb decryptor");
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
    EXPECT_STREQ(headcode::mem::MemoryToHex(plain).c_str(), "303132333435363738393031323334350000000000000000");
    EXPECT_STREQ(headcode::mem::MemoryToHex(cipher).c_str(), "640250391be5f0a5c7ba93904385f8330000000000000000");
}


TEST(SymmetricCipher_OpenSSL_AES_192_ECB, regular) {

    auto algo_enc = headcode::crypt::Factory::Create("openssl-aes-192-ecb encryptor");
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

    auto algo_dec = headcode::crypt::Factory::Create("openssl-aes-192-ecb decryptor");
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
