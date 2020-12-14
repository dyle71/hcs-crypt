/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <gtest/gtest.h>

#include "../../../src/bin/cli.hpp"


TEST(Crypt_cli, version_short) {

    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("-V");
    char * argv[2] = {argv_1, argv_2};

    auto cryptoClientArguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(cryptoClientArguments.version_);
    EXPECT_TRUE(cryptoClientArguments.IsConfigOk());
    EXPECT_FALSE(cryptoClientArguments.proceed_);
}


TEST(Crypt_cli, version_long) {


    char * argv_1 = strdup("crypt");
    char * argv_2 = strdup("--version");
    char * argv[2] = {argv_1, argv_2};

    auto cryptoClientArguments = ParseCommandLine(2, argv);
    EXPECT_TRUE(cryptoClientArguments.version_);
    EXPECT_TRUE(cryptoClientArguments.IsConfigOk());
    EXPECT_FALSE(cryptoClientArguments.proceed_);
}
