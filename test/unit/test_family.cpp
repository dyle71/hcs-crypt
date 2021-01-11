/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>


TEST(Family, text_symmetric_cypher) {
    auto text = headcode::crypt::GetFamilyText(headcode::crypt::Family::SYMMETRIC_CIPHER);
    EXPECT_FALSE(text.empty());
}


TEST(Family, text_hash) {
    auto text = headcode::crypt::GetFamilyText(headcode::crypt::Family::HASH);
    EXPECT_FALSE(text.empty());
}


TEST(Family, text_unknown) {
    auto text = headcode::crypt::GetFamilyText(headcode::crypt::Family::UNKNOWN);
    EXPECT_FALSE(text.empty());
}
