/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_PADDING_HPP
#define HEADCODE_SPACE_CRYPT_PADDING_HPP

#include <cstdint>
#include <vector>

namespace headcode::crypt {


/**
 * @brief   Different padding stratgies to fill up the remaining space in blocks.
 * See http://www.crypto-it.net/eng/theory/padding.html
 */
enum class PaddingStrategy {

    /**
     * @brief   No padding at all.
     */
    PADDING_NONE = 0x0000,

    /**
     * @brief   PKCS#5 and PKCS#7 padding.
     * The value of each pad byte is the total number of bytes that are added.
     */
    PADDING_PKCS_5_7,

    /**
     * @brief   ISO 7816-4 padding.
     * The first byte of the padding is 0x80. All other bytes of the padding are zeros.
     */
    PADDING_ISO_7816_4,

    /**
     * @brief   ISO 10126-2 padding.
     * The last byte of the padding (thus, the last byte of the block) is the number of pad bytes.
     * All other bytes of the padding are some random data.
     */
    PADDING_ISO_10126_2,

    /**
     * @brief   ANSI X9.23 padding.
     * The last byte of the padding (thus, the last byte of the block) is the number of pad bytes.
     * All other bytes of the padding are zeros.
     */
    PADDING_ANSI_X9_23,

    /**
     * @brief   All padding bytes are zeros.
     */
    PADDING_ZERO
};


/**
 * @brief   Perform padding on the given block.
 * @param   block                   the block to be padded.
 * @param   size                    the desired size
 * @param   padding_strategy        The padding strategy applied.
 */
void Pad(std::vector<std::byte> & block, std::uint64_t size, PaddingStrategy padding_strategy);


}


#endif