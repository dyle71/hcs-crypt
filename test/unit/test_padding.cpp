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


/**
 * @param   Parameterized test fixture class.
 */
class TestPaddingVector
        : public testing::TestWithParam<
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


TEST_P(TestPaddingVector, padding_paramterized) {

    headcode::crypt::PaddingStrategy padding_strategy = ::testing::get<0>(GetParam());
    ASSERT_FALSE(headcode::crypt::GetPaddingStrategyText(padding_strategy).empty());

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


/**
 * @param   Parameterized test fixture class.
 */
class TestPaddingCArray
        : public testing::TestWithParam<
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


TEST_P(TestPaddingCArray, padding_paramterized) {

    headcode::crypt::PaddingStrategy padding_strategy = ::testing::get<0>(GetParam());
    ASSERT_FALSE(headcode::crypt::GetPaddingStrategyText(padding_strategy).empty());

    std::uint64_t padding_size = ::testing::get<1>(GetParam());
    std::vector<std::byte> const & input = ::testing::get<2>(GetParam());

    std::uint64_t current_size = input.size();
    std::uint64_t total_size = current_size;

    if ((padding_size > 0) && ((total_size % padding_size) != 0)) {
        total_size += padding_size - (total_size % padding_size);
    }

    auto block = new unsigned char[total_size];
    std::memcpy(block, input.data(), current_size);
    headcode::crypt::Pad(block, total_size, current_size, padding_size, padding_strategy);

    if ((total_size == input.size()) || (padding_strategy == headcode::crypt::PaddingStrategy::PADDING_NONE)) {

        // no padding ==> no change and block size is a multiple of size
        if ((padding_size != 0) && (padding_strategy != headcode::crypt::PaddingStrategy::PADDING_NONE)) {
            EXPECT_EQ(input.size() % padding_size, 0ul);
        }
        EXPECT_EQ(std::memcmp(block, input.data(), current_size), 0);

    } else {

        auto padded_size = total_size - input.size();
        EXPECT_TRUE(padded_size > 0);
        EXPECT_EQ(total_size % padding_size, 0u);
        ASSERT_EQ(std::memcmp(block, input.data(), input.size()), 0);
        auto padded_start = reinterpret_cast<unsigned char *>(block + input.size());
        auto padded_end = reinterpret_cast<unsigned char *>(block + total_size);
        auto padded_byte = padded_start;

        switch (padding_strategy) {

            case headcode::crypt::PaddingStrategy::PADDING_PKCS_5_7:
                // PADDING_PKCS_5_7: The value of each pad byte is the total number of bytes that are added.
                while (padded_byte != padded_end) {
                    EXPECT_EQ(*padded_byte, padded_size);
                    padded_byte++;
                }
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ANSI_X9_23:
                // PADDING_ANSI_X9_23: The last byte of the padding (thus, the last byte of the block) is the
                // number of pad bytes. All other bytes of the padding are zeros.
                while (padded_byte != padded_end - 1) {
                    EXPECT_EQ(*padded_byte, 0);
                    padded_byte++;
                }
                EXPECT_EQ(*padded_byte, padded_size);
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ISO_7816_4:
                // PADDING_ISO_7816_4: The first byte of the padding is 0x80. All other bytes of the padding
                // are zeros.
                EXPECT_EQ(*padded_byte, 0x80u);
                padded_byte++;
                while (padded_byte != padded_end) {
                    EXPECT_EQ(*padded_byte, 0);
                    padded_byte++;
                }
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ZERO:
                // PADDING_ZERO: All padding bytes are zeros.
                while (padded_byte != padded_end) {
                    EXPECT_EQ(*padded_byte, 0u);
                    padded_byte++;
                }
                break;

            case headcode::crypt::PaddingStrategy::PADDING_ISO_10126_2:
                // PADDING_ISO_10126_2: The last byte of the padding (thus, the last byte of the block)
                // is the number of pad bytes. All other bytes of the padding are some random data.
                EXPECT_EQ(*(padded_end - 1), padded_size);
                break;

            default:
                break;
        }
    }

    delete[] block;
}


static std::string const kIpsumLorem10 = "Lorem ipsu";

static std::string const kIpsumLorem15 = "Lorem ipsum dol";

static std::string const kIpsumLorem16 = "Lorem ipsum dolo";

static std::string const kIpsumLorem17 = "Lorem ipsum dolor";

static std::string const kIpsumLorem27 = "Lorem ipsum dolor sit amet,";

static std::string const kIpsumLorem32 = "Lorem ipsum dolor sit amet, cons";

static std::string const kIpsumLorem33 = "Lorem ipsum dolor sit amet, conse";

static std::string const kIpsumLorem60 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed ";

static std::string const kIpsumLorem64 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eius";

static std::string const kIpsumLorem65 = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusm";

static std::string const kIpsumLoremLong =
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


static auto kInputPaddingStrategies = ::testing::Values(headcode::crypt::PaddingStrategy::PADDING_NONE,
                                                        headcode::crypt::PaddingStrategy::PADDING_PKCS_5_7,
                                                        headcode::crypt::PaddingStrategy::PADDING_ISO_7816_4,
                                                        headcode::crypt::PaddingStrategy::PADDING_ISO_10126_2,
                                                        headcode::crypt::PaddingStrategy::PADDING_ANSI_X9_23,
                                                        headcode::crypt::PaddingStrategy::PADDING_ZERO);

static auto kInputSize = ::testing::Values(0, 16, 32, 64);


static auto kInputValues = ::testing::Values(headcode::mem::StringToMemory(kIpsumLorem10),
                                             headcode::mem::StringToMemory(kIpsumLorem15),
                                             headcode::mem::StringToMemory(kIpsumLorem16),
                                             headcode::mem::StringToMemory(kIpsumLorem17),
                                             headcode::mem::StringToMemory(kIpsumLorem27),
                                             headcode::mem::StringToMemory(kIpsumLorem32),
                                             headcode::mem::StringToMemory(kIpsumLorem33),
                                             headcode::mem::StringToMemory(kIpsumLorem60),
                                             headcode::mem::StringToMemory(kIpsumLorem64),
                                             headcode::mem::StringToMemory(kIpsumLorem65),
                                             headcode::mem::StringToMemory(kIpsumLoremLong));


INSTANTIATE_TEST_SUITE_P(padding,
                         TestPaddingVector,
                         ::testing::Combine(kInputPaddingStrategies, kInputSize, kInputValues));


INSTANTIATE_TEST_SUITE_P(padding,
                         TestPaddingCArray,
                         ::testing::Combine(kInputPaddingStrategies, kInputSize, kInputValues));
