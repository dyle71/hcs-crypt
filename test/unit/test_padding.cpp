/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <gtest/gtest.h>

#include <headcode/crypt/crypt.hpp>
#include <headcode/mem/mem.hpp>

#include "shared/ipsum_lorem.hpp"


std::string const IPSUM_LOREM_10 = "Lorem ipsu";

std::string const IPSUM_LOREM_15 = "Lorem ipsum dol";

std::string const IPSUM_LOREM_16 = "Lorem ipsum dolo";

std::string const IPSUM_LOREM_17 = "Lorem ipsum dolor";

std::string const IPSUM_LOREM_27 = "Lorem ipsum dolor sit amet,";

std::string const IPSUM_LOREM_32 = "Lorem ipsum dolor sit amet, cons";

std::string const IPSUM_LOREM_33 = "Lorem ipsum dolor sit amet, conse";

std::string const IPSUM_LOREM_60 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed "

std::string const IPSUM_LOREM_64 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eius"

std::string const IPSUM_LOREM_65 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusm"

std::string const IPSUM_LOREM_LONG =
        "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eius"
        "mod tempor incidunt ut labore et dolore magna aliqua. Ut enim ad"
        "minim veniam, quis nostrud exercitation ullamco laboris nisi ut "
        "aliquid ex ea commodi consequat. Quis aute iure reprehenderit in"
        "voluptate velit esse cillum dolore eu fugiat nulla pariatur. Exc"
        "epteur sint obcaecat cupiditat non proident, sunt in culpa qui o"
        "fficia deserunt mollit anim id est laborum. Duis autem vel eum i"
        "riure dolor in hendrerit in vulputate velit esse molestie conseq"
        "uat, vel illum dolore eu feugiat nulla facilisis at vero eros et"
        "accumsan et iusto odio dignissim qui blandit praesent luptatum z"
        "zril delenit augue duis dolore te feugait nulla facilisi. Lorem "
        "ipsum dolor sit amet, consectetuer adipiscing elit, sed diam non"
        "ummy nibh euismod tincidunt ut laoreet dolore magna aliquam erat"
        "volutpat.";


TEST(Padding, padding_none_empty) {

    std::vector<std::byte> block;
    headcode::crypt::Pad(block, 0, headcode::crypt::PaddingStrategy::PADDING_NONE);

    EXPECT_EQ(block.size(), 0);
}


TEST(Padding, padding_none_fit) {

    auto block_16 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);
    auto block_32 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);
    auto block_64 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);

    headcode::crypt::Pad(block_16, 16, headcode::crypt::PaddingStrategy::PADDING_NONE);
    headcode::crypt::Pad(block_32, 32, headcode::crypt::PaddingStrategy::PADDING_NONE);
    headcode::crypt::Pad(block_64, 64, headcode::crypt::PaddingStrategy::PADDING_NONE);

    EXPECT_EQ(block_0.size(), 0);
}


TEST(Padding, padding_none_pad) {

    auto block_16 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);
    auto block_32 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);
    auto block_64 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);

    headcode::crypt::Pad(block_16, 16, headcode::crypt::PaddingStrategy::PADDING_NONE);
    headcode::crypt::Pad(block_32, 32, headcode::crypt::PaddingStrategy::PADDING_NONE);
    headcode::crypt::Pad(block_64, 64, headcode::crypt::PaddingStrategy::PADDING_NONE);

    EXPECT_EQ(block_0.size(), 0);
}


TEST(Padding, padding_none_multiple) {

    auto block_16 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);
    auto block_32 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);
    auto block_64 = headcode::mem::StringToMemory(IPSUM_LOREM_TEXT);

    headcode::crypt::Pad(block_16, 16, headcode::crypt::PaddingStrategy::PADDING_NONE);
    headcode::crypt::Pad(block_32, 32, headcode::crypt::PaddingStrategy::PADDING_NONE);
    headcode::crypt::Pad(block_64, 64, headcode::crypt::PaddingStrategy::PADDING_NONE);

    EXPECT_EQ(block_0.size(), 0);
}
