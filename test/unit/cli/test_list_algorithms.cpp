/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <set>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include "shared/split_lines.hpp"
#include "shared/trim_string.hpp"

#include "../../../src/bin/list_algorithms.hpp"



static std::set<std::string> const kAlgorithms{

        "openssl-aes-192-ecb-encryptor",
        "openssl-aes-256-ecb-encryptor",
        "openssl-aes-128-ecb-encryptor",
        "openssl-aes-192-ecb-decryptor",
        "openssl-aes-256-ecb-decryptor",
        "openssl-aes-128-ecb-decryptor",
        "openssl-aes-192-cbc-encryptor",
        "openssl-aes-256-cbc-encryptor",
        "openssl-aes-192-cbc-decryptor",
        "openssl-aes-128-cbc-encryptor",
        "openssl-aes-256-cbc-decryptor",
        "openssl-aes-128-cbc-decryptor",
        "ltc-aes-256-ecb-encryptor",
        "ltc-aes-192-ecb-decryptor",
        "ltc-aes-256-ecb-decryptor",
        "ltc-aes-128-ecb-encryptor",
        "ltc-aes-128-ecb-decryptor",
        "ltc-aes-192-ecb-encryptor",
        "ltc-aes-256-cbc-decryptor",
        "ltc-aes-192-cbc-encryptor",
        "ltc-aes-128-cbc-decryptor",
        "ltc-aes-192-cbc-decryptor",
        "ltc-aes-128-cbc-encryptor",
        "ltc-aes-256-cbc-encryptor",
        "copy",
        "openssl-md5",
        "openssl-sha1",
        "openssl-ripemd160",
        "openssl-sha384",
        "openssl-sha512",
        "openssl-sha256",
        "openssl-sha224",
        "ltc-ripemd320",
        "ltc-sha224",
        "ltc-tiger192",
        "ltc-sha512",
        "ltc-ripemd160",
        "ltc-ripemd128",
        "ltc-md5",
        "ltc-sha256",
        "ltc-sha384",
        "ltc-ripemd256",
        "ltc-sha1",
        "nohash"};


TEST(Crypt_list_algorithms, regular) {

    std::stringstream ss;
    ListAlgorithms(ss);

    static std::set<std::string> const kNonAlgorithmOutput{std::string{}, "Symmetric Ciphers", "Hashes"};

    auto lines = Split(ss.str());
    for (auto const & line : lines) {

        if (kNonAlgorithmOutput.find(line) != kNonAlgorithmOutput.end()) {
            continue;
        }

        std::cout << line << std::endl;
        auto iter = kAlgorithms.find(Trim(line));
        ASSERT_FALSE(iter == kAlgorithms.end());
    }
}
