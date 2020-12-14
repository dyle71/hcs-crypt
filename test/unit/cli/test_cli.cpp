/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <gtest/gtest.h>

#include "../../../src/bin/cli.hpp"


TEST(Crypt_cli, verbose_short) {

    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("-v");
    char * argv[2] = {argv_1, argv_2};

    auto crypto_client_arguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(crypto_client_arguments.verbose_);
    EXPECT_FALSE(crypto_client_arguments.IsConfigOk());
    EXPECT_FALSE(crypto_client_arguments.proceed_);
}


TEST(Crypt_cli, verbose_long) {


    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("--verbose");
    char * argv[2] = {argv_1, argv_2};

    auto crypto_client_arguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(crypto_client_arguments.verbose_);
    EXPECT_FALSE(crypto_client_arguments.IsConfigOk());
    EXPECT_FALSE(crypto_client_arguments.proceed_);
}


TEST(Crypt_cli, version_short) {

    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("-V");
    char * argv[2] = {argv_1, argv_2};

    auto crypto_client_arguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(crypto_client_arguments.version_);
    EXPECT_TRUE(crypto_client_arguments.IsConfigOk());
    EXPECT_FALSE(crypto_client_arguments.proceed_);
}


TEST(Crypt_cli, version_long) {


    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("--version");
    char * argv[2] = {argv_1, argv_2};

    auto crypto_client_arguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(crypto_client_arguments.version_);
    EXPECT_TRUE(crypto_client_arguments.IsConfigOk());
    EXPECT_FALSE(crypto_client_arguments.proceed_);
}
