/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <regex>
#include <string>

#include <gtest/gtest.h>

#include "shared/split_lines.hpp"

#include "../../../src/bin/start.hpp"


TEST(Crypt_start, version) {

    std::stringstream ss_in;
    std::stringstream ss_out;
    std::stringstream ss_err;

    std::vector<char *> argv = {strdup("test"), strdup("--version")};
    ASSERT_EQ(Start(argv.size(), argv.data(), ss_in, ss_out, ss_err), 0);

    auto result = Split(ss_out.str());
    ASSERT_GE(result.size(), 1ul);

    static std::regex const re{R"(crypt v\d\d*\.\d\d*\.\d\d*)"};
    std::smatch m;
    EXPECT_TRUE(std::regex_match(result.at(0), m, re));

    for (auto arg : argv) {
        free(arg);
    }
}


TEST(Crypt_start, help) {

    std::stringstream ss_in;
    std::stringstream ss_out;
    std::stringstream ss_err;

    std::vector<char *> argv = {strdup("test"), strdup("--help")};
    ASSERT_EQ(Start(argv.size(), argv.data(), ss_in, ss_out, ss_err), 0);

    auto result = Split(ss_out.str());
    ASSERT_GE(result.size(), 1ul);

    for (auto arg : argv) {
        free(arg);
    }
}


TEST(Crypt_start, unknown_option) {

    std::stringstream ss_in;
    std::stringstream ss_out;
    std::stringstream ss_err;

    std::vector<char *> argv = {strdup("test"), strdup("--fail-this-option")};
    ASSERT_NE(Start(argv.size(), argv.data(), ss_in, ss_out, ss_err), 0);

    auto result = Split(ss_err.str());
    ASSERT_GE(result.size(), 1ul);

    for (auto arg : argv) {
        free(arg);
    }
}


TEST(Crypt_start, list) {

    std::stringstream ss_in;
    std::stringstream ss_out;
    std::stringstream ss_err;

    std::vector<char *> argv = {strdup("test"), strdup("--list")};
    ASSERT_EQ(Start(argv.size(), argv.data(), ss_in, ss_out, ss_err), 0);

    auto lines = Split(ss_out.str());
    EXPECT_GT(lines.size(), 0ul);

    for (auto arg : argv) {
        free(arg);
    }
}


TEST(Crypt_start, explain_md5) {

    std::stringstream ss_in;
    std::stringstream ss_out;
    std::stringstream ss_err;

    std::vector<char *> argv = {strdup("test"), strdup("--explain"), strdup("ltc-md5")};
    ASSERT_EQ(Start(argv.size(), argv.data(), ss_in, ss_out, ss_err), 0);

    auto lines = Split(ss_out.str());
    EXPECT_GT(lines.size(), 0ul);

    for (auto arg : argv) {
        free(arg);
    }
}
