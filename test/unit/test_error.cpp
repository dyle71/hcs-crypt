/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>


TEST(Error, text_no_error) {
    auto text = headcode::crypt::GetErrorText(headcode::crypt::Error::kNoError);
    EXPECT_FALSE(text.empty());
}


TEST(Error, text_invalid_argument) {
    auto text = headcode::crypt::GetErrorText(headcode::crypt::Error::kInvalidArgument);
    EXPECT_FALSE(text.empty());
}


TEST(Error, text_invalid_operation) {
    auto text = headcode::crypt::GetErrorText(headcode::crypt::Error::kInvalidOperation);
    EXPECT_FALSE(text.empty());
}
