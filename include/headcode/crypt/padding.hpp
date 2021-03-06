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
 * @brief   Returns a human readable name for the padding strategy.
 * @return  A text describing naming the padding strategy.
 */
std::string const & GetPaddingStrategyText(PaddingStrategy padding_strategy);


/**
 * @brief   Perform padding on the given block.
 * @param   block                   the block to be padded.
 * @param   size                    the desired size (must not exceed 255).
 * @param   padding_strategy        The padding strategy applied.
 */
void Pad(std::vector<std::byte> & block, std::uint64_t size, PaddingStrategy padding_strategy);


/**
 * @brief   Perform padding on the given block.
 *
 * This is the "low level" padding function operating on C arrays.
 * Avoid this and use the byte-vector function instead, unless you know exactly what you are doing.
 * total_size must be greater than current_size by a padding_size max.
 *
 * @param   block                   the block memory to be padded.
 * @param   total_size              the total size of block (all what is allocated [total_size >= current_size]).
 * @param   current_size            the current size of block data (up to which point do we have data).
 * @param   padding_size            the desired padding size (must not exceed 255).
 * @param   padding_strategy        The padding strategy applied.
 */
void Pad(unsigned char * block,
         std::uint64_t total_size,
         std::uint64_t current_size,
         std::uint64_t padding_size,
         PaddingStrategy padding_strategy);


}


#endif
