/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_EXPLAIN_ALGORITHM_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_EXPLAIN_ALGORITHM_HPP

#include <ostream>


/**
 * @brief   Explain an algorithm.
 * @param   out         the stream to push the information too
 * @param   name        the name of the algorithm to explain.
 */
void ExplainAlgorithm(std::ostream & out, std::string const & name);


#endif
