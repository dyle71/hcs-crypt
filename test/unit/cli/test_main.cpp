/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>




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


/**
 * @brief   Splits the content of the given str.
 * @param   str             the string to split.
 * @param   delim           the delimiter used.
 * @return  the lines produced.
 */
static std::vector<std::string> Split(std::string const & str, char delim = '\n') {

    std::vector<std::string> res;
    res.clear();

    std::stringstream ss{str};
    std::string line;
    while (std::getline(ss, line, delim)) {
        res.push_back(line);
    }

    return res;
}


/**
 * @brief   Strips all whitespace from start and end of a string.
 * @param   str     the string to strip
 * @return  same as str but all whitespaces removed.
 */
static std::string Trim(std::string str) {

    static std::regex const re{R"(\s*(.*)\s*)"};
    std::smatch m;
    if (std::regex_match(str, m, re)) {
        str = m[1].str();
    }
    return str;
}


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
