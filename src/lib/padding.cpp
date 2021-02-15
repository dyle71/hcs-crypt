/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cstring>
#include <map>
#include <random>

#include <headcode/logger/logger.hpp>
#include <headcode/crypt/padding.hpp>


/**
 * @brief   Draw a random value.
 * @return  A random value.
 */
static unsigned char RandomChar() {
    static std::random_device rd;
    return rd() % 256;
}


std::string const & headcode::crypt::GetPaddingStrategyText(PaddingStrategy padding_strategy) {

    static std::map<headcode::crypt::PaddingStrategy, std::string> const known_padding_strategy_texts = {
            {headcode::crypt::PaddingStrategy::PADDING_NONE, "NONE"},
            {headcode::crypt::PaddingStrategy::PADDING_PKCS_5_7, "PKCS#5, PKCS#7"},
            {headcode::crypt::PaddingStrategy::PADDING_ISO_7816_4, "ISO 7816-4"},
            {headcode::crypt::PaddingStrategy::PADDING_ISO_10126_2, "ISO 10126-2"},
            {headcode::crypt::PaddingStrategy::PADDING_ANSI_X9_23, "ANSI X9.23"},
            {headcode::crypt::PaddingStrategy::PADDING_ZERO, "Zero Bytes"}};

    auto iter = known_padding_strategy_texts.find(padding_strategy);

    if (iter == known_padding_strategy_texts.end()) {
        headcode::logger::Warning{"headcode.crypt"} << "Unknown padding strategy.";
        static std::string const null_string;
        return null_string;
    }
    return iter->second;
}


void headcode::crypt::Pad(std::vector<std::byte> & block, std::uint64_t size, PaddingStrategy padding_strategy) {

    if (size > 255) {
        headcode::logger::Warning{"headcode.crypt"} << "Size if out of range for padding.";
        return;
    }
    if (size == 0) {
        headcode::logger::Warning{"headcode.crypt"} << "Block size of padding may not be 0.";
        return;
    }

    auto current_size = block.size();
    unsigned char padded_size = current_size % size;
    if ((padded_size != 0) && (padding_strategy != PaddingStrategy::PADDING_NONE)) {
        block.resize((block.size() / size + 1) * size);
    }
    auto total_size = block.size();

    Pad(reinterpret_cast<unsigned char *>(block.data()), total_size, current_size, size, padding_strategy);
}


void headcode::crypt::Pad(unsigned char * block,
                          std::uint64_t total_size,
                          std::uint64_t current_size,
                          std::uint64_t padding_size,
                          PaddingStrategy padding_strategy) {

    if ((block == nullptr) || (total_size == 0) || (total_size <= current_size)) {
        headcode::logger::Warning{"headcode.crypt"} << "Input values for padding invalid.";
        return;
    }
    if (padding_size > 255) {
        headcode::logger::Warning{"headcode.crypt"} << "Size out of range for padding.";
        return;
    }
    if (padding_size == 0) {
        headcode::logger::Warning{"headcode.crypt"} << "Block size of padding may not be 0.";
        return;
    }
    if (total_size < padding_size) {
        headcode::logger::Warning{"headcode.crypt"} << "Memory block size below padding size.";
    }

    unsigned char padded_size = current_size % padding_size;
    if ((padded_size == 0) || (padding_strategy == headcode::crypt::PaddingStrategy::PADDING_NONE)) {
        return;
    }
    padded_size = padding_size - padded_size;

    auto padded_end = block + total_size;
    auto padded_byte = padded_end - padded_size;
    switch (padding_strategy) {

        case headcode::crypt::PaddingStrategy::PADDING_PKCS_5_7:
            // PADDING_PKCS_5_7: The value of each pad byte is the total number of bytes that are added.
            std::memset(padded_byte, padded_size, padded_size);
            break;

        case headcode::crypt::PaddingStrategy::PADDING_ANSI_X9_23:
            // PADDING_ANSI_X9_23: The last byte of the padding (thus, the last byte of the block) is the
            // number of pad bytes. All other bytes of the padding are zeros.
            std::memset(padded_byte, 0, padded_size - 1);
            padded_byte[padded_size - 1] = padded_size;
            break;

        case headcode::crypt::PaddingStrategy::PADDING_ISO_7816_4:
            // PADDING_ISO_7816_4: The first byte of the padding is 0x80.
            // All other bytes of the padding are zeros.
            *padded_byte = 0x80;
            std::memset(padded_byte + 1, 0, padded_size - 1);
            break;

        case headcode::crypt::PaddingStrategy::PADDING_ZERO:
            // PADDING_ZERO: All padding bytes are zeros.
            std::memset(padded_byte, 0, padded_size);
            break;

        case headcode::crypt::PaddingStrategy::PADDING_ISO_10126_2:
            // PADDING_ISO_10126_2: The last byte of the padding (thus, the last byte of the block)
            // is the number of pad bytes. All other bytes of the padding are some random data.
            while (padded_byte != padded_end - 1) {
                *padded_byte = RandomChar();
                padded_byte++;
            }
            *padded_byte = padded_size;
            break;

        default:
            break;
    }
}
