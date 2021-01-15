/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include "../../../src/bin/cli.hpp"


TEST(Crypt_cli, version_long) {


    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("--version");
    char * argv[2] = {argv_1, argv_2};

    auto crypto_client_arguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(crypto_client_arguments.version_);
    EXPECT_TRUE(crypto_client_arguments.IsConfigOk());
    EXPECT_FALSE(crypto_client_arguments.explain_algorithm_);
    EXPECT_FALSE(crypto_client_arguments.list_algorithms_);
}


TEST(Crypt_cli, explain_algorithm_none) {

    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("--explain");
    char * argv[2] = {argv_1, argv_2};

    auto crypto_client_arguments = ParseCommandLine(2, argv);
    EXPECT_FALSE(crypto_client_arguments.IsConfigOk());
    EXPECT_TRUE(crypto_client_arguments.explain_algorithm_);
    EXPECT_FALSE(crypto_client_arguments.list_algorithms_);
}


TEST(Crypt_cli, explain_algorithm_md5) {

    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("--explain");
    char * argv_3 = strdup("ltc-md5");
    char * argv[3] = {argv_1, argv_2, argv_3};

    auto crypto_client_arguments = ParseCommandLine(3, argv);
    EXPECT_TRUE(crypto_client_arguments.IsConfigOk());
    EXPECT_TRUE(crypto_client_arguments.explain_algorithm_);
    EXPECT_FALSE(crypto_client_arguments.list_algorithms_);
    EXPECT_STREQ(crypto_client_arguments.algorithm_.c_str(), "ltc-md5");
}


TEST(Crypt_cli, list_algorithms) {

    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("--list");
    char * argv[2] = {argv_1, argv_2};

    auto crypto_client_arguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(crypto_client_arguments.IsConfigOk());
    EXPECT_FALSE(crypto_client_arguments.explain_algorithm_);
    EXPECT_TRUE(crypto_client_arguments.list_algorithms_);
}


TEST(Crypt_cli, void_command) {

    char * argv_1 = strdup("crypt");
    char * argv[1] = {argv_1};

    auto crypto_client_arguments = ParseCommandLine(1, argv);
    EXPECT_FALSE(crypto_client_arguments.IsConfigOk());
    EXPECT_FALSE(crypto_client_arguments.explain_algorithm_);
    EXPECT_FALSE(crypto_client_arguments.list_algorithms_);
}
