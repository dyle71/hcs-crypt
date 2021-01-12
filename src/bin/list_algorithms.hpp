/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_LIST_ALGORITHMS_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_LIST_ALGORITHMS_HPP

#include <ostream>


/**
 * @brief   List all known algorithms to a stream.
 * @param   out         the stream to push the information too
 * @param   verbose     pushes more info.
 */
void ListAlgorithms(std::ostream & out, bool verbose);


#endif
