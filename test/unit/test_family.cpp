/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>


TEST(Family, text_symmetric_cypher) {
    auto text = headcode::crypt::GetFamilyText(headcode::crypt::Family::kSymmetricCipher);
    EXPECT_FALSE(text.empty());
}


TEST(Family, text_hash) {
    auto text = headcode::crypt::GetFamilyText(headcode::crypt::Family::kHash);
    EXPECT_FALSE(text.empty());
}


TEST(Family, text_unknown) {
    auto text = headcode::crypt::GetFamilyText(headcode::crypt::Family::kUnknown);
    EXPECT_FALSE(text.empty());
}
