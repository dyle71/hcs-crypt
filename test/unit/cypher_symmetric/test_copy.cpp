/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>
#include <headcode/mem/mem.hpp>

#include "shared/ipsum_lorem.hpp"

using namespace headcode::crypt;


TEST(CryptSymmetric_Copy, creation) {

    auto algo = Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);

    EXPECT_STREQ(algo->GetName().c_str(), "copy");
    EXPECT_EQ(algo->GetFamily(), Family::CYPHER_SYMMETRIC);
    EXPECT_FALSE(algo->GetDescription().empty());
}


TEST(CryptSymmetric_Copy, regular) {

    auto algo = Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    ASSERT_STREQ(algo->GetName().c_str(), "copy");

    algo->Add(IPSUM_LOREM_TEXT);
    auto cypher = algo->Finalize();

    auto expected = headcode::mem::MemoryToHex(IPSUM_LOREM_TEXT.data(), IPSUM_LOREM_TEXT.size());
    auto result = headcode::mem::MemoryToHex(cypher);

    EXPECT_STREQ(expected.c_str(), result.c_str());
}
