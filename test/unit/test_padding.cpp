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


/**
 * @param   Parameterized test fixture class.
 */
class TestPadding : public testing::TestWithParam<
                            ::testing::tuple<headcode::crypt::PaddingStrategy, std::uint64_t, std::vector<std::byte>>> {

protected:
    /**
     * @brief   Setup the paramterized tests.
     */
    void SetUp() override {
    }

    /**
     * @brief   Wind down the paramterized tests.
     */
    void TearDown() override {
    }
};


TEST_P(TestPadding, padding_paramterized) {

    headcode::crypt::PaddingStrategy padding_strategy = ::testing::get<0>(GetParam());
    std::uint64_t size = ::testing::get<1>(GetParam());
    std::vector<std::byte> const & input = ::testing::get<2>(GetParam());

    std::vector<std::byte> block = input;
    headcode::crypt::Pad(block, size, padding_strategy);

    if ((block.size() == input.size()) || (padding_strategy == headcode::crypt::PaddingStrategy::PADDING_NONE)) {

        // no padding ==> no change and block size is a multiple of size
        if ((size != 0) && (padding_strategy != headcode::crypt::PaddingStrategy::PADDING_NONE)) {
            EXPECT_EQ(input.size() % size, 0ul);
        }
        EXPECT_EQ(std::memcmp(block.data(), input.data(), block.size()), 0);

    } else {

        auto padded_size = block.size() - input.size();
        EXPECT_TRUE(padded_size > 0);
        EXPECT_EQ(block.size() % size, 0u);
        ASSERT_EQ(std::memcmp(block.data(), input.data(), input.size()), 0);
        auto padded_start = reinterpret_cast<unsigned char *>(block.data() + input.size());
        auto padded_end = reinterpret_cast<unsigned char *>(block.data() + block.size());
        auto padded_byte = padded_start;

        switch (padding_strategy) {

            case headcode::crypt::PaddingStrategy::PADDING_PKCS_5_7:
                // PADDING_PKCS_5_7: The value of each pad byte is the total number of bytes that are added.
                while (padded_byte != padded_end) {
                    ASSERT_EQ(*padded_byte, padded_size);
                    padded_byte++;
                }
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ANSI_X9_23:
                // PADDING_ANSI_X9_23: The last byte of the padding (thus, the last byte of the block) is the
                // number of pad bytes. All other bytes of the padding are zeros.
                while (padded_byte != padded_end - 1) {
                    ASSERT_EQ(*padded_byte, 0);
                    padded_byte++;
                }
                ASSERT_EQ(*padded_byte, padded_size);
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ISO_7816_4:
                // PADDING_ISO_7816_4: The first byte of the padding is 0x80. All other bytes of the padding
                // are zeros.
                ASSERT_EQ(*padded_byte, 0x80u);
                padded_byte++;
                while (padded_byte != padded_end) {
                    ASSERT_EQ(*padded_byte, 0);
                    padded_byte++;
                }
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ZERO:
                // PADDING_ZERO: All padding bytes are zeros.
                while (padded_byte != padded_end) {
                    ASSERT_EQ(*padded_byte, 0u);
                    padded_byte++;
                }
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ISO_10126_2:
                // PADDING_ISO_10126_2: The last byte of the padding (thus, the last byte of the block)
                // is the number of pad bytes. All other bytes of the padding are some random data.
                ASSERT_EQ(*(padded_end - 1), padded_size);
                break;

            default:
                break;
        }
    }
}


static std::string const IPSUM_LOREM_10 = "Lorem ipsu";

static std::string const IPSUM_LOREM_15 = "Lorem ipsum dol";

static std::string const IPSUM_LOREM_16 = "Lorem ipsum dolo";

static std::string const IPSUM_LOREM_17 = "Lorem ipsum dolor";

static std::string const IPSUM_LOREM_27 = "Lorem ipsum dolor sit amet,";

static std::string const IPSUM_LOREM_32 = "Lorem ipsum dolor sit amet, cons";

static std::string const IPSUM_LOREM_33 = "Lorem ipsum dolor sit amet, conse";

static std::string const IPSUM_LOREM_60 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed ";

static std::string const IPSUM_LOREM_64 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eius";

static std::string const IPSUM_LOREM_65 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusm";

static std::string const IPSUM_LOREM_LONG =
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


static auto INPUT_PADDING_STRATEGIES = ::testing::Values(headcode::crypt::PaddingStrategy::PADDING_NONE,
                                                         headcode::crypt::PaddingStrategy::PADDING_PKCS_5_7,
                                                         headcode::crypt::PaddingStrategy::PADDING_ISO_7816_4,
                                                         headcode::crypt::PaddingStrategy::PADDING_ISO_10126_2,
                                                         headcode::crypt::PaddingStrategy::PADDING_ANSI_X9_23,
                                                         headcode::crypt::PaddingStrategy::PADDING_ZERO);

static auto INPUT_SIZES = ::testing::Values(0, 16, 32, 64);


static auto INPUT_VALUES = ::testing::Values(headcode::mem::StringToMemory(IPSUM_LOREM_10),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_15),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_16),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_17),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_27),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_32),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_33),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_60),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_64),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_65),
                                             headcode::mem::StringToMemory(IPSUM_LOREM_LONG));


INSTANTIATE_TEST_SUITE_P(padding, TestPadding, ::testing::Combine(INPUT_PADDING_STRATEGIES, INPUT_SIZES, INPUT_VALUES));
