/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_PROCESSING_BLOCK_SIZE_HPP
#define HEADCODE_SPACE_CRYPT_PROCESSING_BLOCK_SIZE_HPP

namespace headcode::crypt {


/**
 * @brief   This enumerates different sizes of a processed block during the Add() operation.

 * When an algorithm is given some data to operate with Add(), it might produce
 * an output block during this execution.
 */
enum class ProcessingBlockSize {
    kEmpty = 0,        //!< @brief The Add() method does not produce any output.
    kSame,             //!< @brief The Add() method does produce output of the same size of the input.
    kLess,             //!< @brief The Add() method does produce less output (but not none) compared to the input.
    kMore              //!< @brief The Add() method does produce more output compared to the input.
};


}


#endif
