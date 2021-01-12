/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <headcode/crypt/version.hpp>


TEST(Version, regular) {
    std::uint32_t version = MAKE_VERSION(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
    EXPECT_EQ(headcode::crypt::GetCurrentVersion(), version);
    EXPECT_STREQ(headcode::crypt::GetVersionString().c_str(), VERSION);
}


TEST(Version, V0_0_1) {
    std::uint32_t version = MAKE_VERSION(0, 0, 1);
    EXPECT_EQ(static_cast<unsigned int>((0) << 24 | (0) << 16 | (1)), version);
    EXPECT_EQ(GetHCSCryptVersion_0_0_1(), version);
}
