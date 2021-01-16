/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <cstring>
#include <iostream>

#include <headcode/crypt/crypt.hpp>

TEST(HelloWorld, hello_world) {

    unsigned char key[16];
    std::memcpy(key, "This is my secret key.", 16);

    unsigned char iv[16];
    std::memcpy(iv, "This is an initialization vector.", 16);

    // grab an AES 256 CBC Encryptor
    auto algorithm = headcode::crypt::Factory::Create("openssl-aes-128-cbc-encryptor");
    algorithm->Initialize({{"key", {key, 16}}, {"iv", {iv, 16}}});

    // encrypt some data (note: the input will be padded!)
    std::vector<std::byte> cipher;
    algorithm->Add("Hello World!", cipher);

    // show the cipher
    for (unsigned int i = 0; i < cipher.size(); ++i) {
        std::cout << std::to_integer<int>(cipher[i]) << " ";
    }
    std::cout << std::endl;

    EXIT_SUCCESS;
}
