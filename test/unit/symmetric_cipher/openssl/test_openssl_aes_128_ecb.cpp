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


TEST(SymmetricCipher_OpenSSL_AES_128_ECB, creation) {

    auto algo = headcode::crypt::Factory::Create("openssl-aes-128-ecb encryptor");
    ASSERT_NE(algo.get(), nullptr);

    headcode::crypt::Algorithm::Description const & description = algo->GetDescription();

    EXPECT_STREQ(description.name_.c_str(), "openssl-aes-128-ecb encryptor");
    EXPECT_EQ(description.family_, headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(description.description_short_.empty());
    EXPECT_FALSE(description.description_long_.empty());
    EXPECT_EQ(description.block_size_incoming_, 16ul);
    EXPECT_EQ(description.block_size_outgoing_, 16ul);
    EXPECT_EQ(description.result_size_, 0ul);

    EXPECT_FALSE(description.final_argument_.needed_);
    EXPECT_TRUE(description.initial_argument_.needed_);
}


TEST(SymmetricCipher_OpenSSL_AES_128_ECB, single_block) {

    auto algo_enc = headcode::crypt::Factory::Create("openssl-aes-128-ecb encryptor");
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

    auto plain = algo_enc->GrowToBlockSize("0123456789012345", algo_enc->GetDescription().block_size_incoming_);
    plain.resize(algo_enc->GetDescription().block_size_incoming_);
    std::vector<std::byte> cipher{plain.size()};
    EXPECT_EQ(algo_enc->Add(plain, cipher), 0);

    // TODO: check cipher
    std::cout << key << std::endl;
    std::cout << headcode::mem::MemoryToHex(plain) << std::endl;
    std::cout << headcode::mem::MemoryToHex(cipher) << std::endl;

    std::vector<std::byte> result_enc;
    EXPECT_EQ(algo_enc->Finalize(result_enc), 0);
    EXPECT_TRUE(result_enc.empty());

    auto algo_dec = headcode::crypt::Factory::Create("ltc-aes-128-ecb decryptor");
    ASSERT_NE(algo_dec.get(), nullptr);
    std::vector<std::byte> plain_decrypted{cipher.size()};
    EXPECT_EQ(algo_dec->Add(cipher, plain_decrypted), 0);
    std::cout << headcode::mem::MemoryToHex(plain_decrypted) << std::endl;
}
