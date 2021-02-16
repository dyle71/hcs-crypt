/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_TEST_SHARED_SPLIT_LINES_HPP
#define HEADCODE_SPACE_CRYPT_TEST_SHARED_SPLIT_LINES_HPP

#include <sstream>
#include <string>
#include <vector>


/**
 * @brief   Splits the content of the given str.
 * @param   str             the string to split.
 * @param   delim           the delimiter used.
 * @return  the lines produced.
 */
static std::vector<std::string> Split(std::string const & str, char delim = '\n') {

    std::vector<std::string> res;
    res.clear();

    std::stringstream ss{str};
    std::string line;
    while (std::getline(ss, line, delim)) {
        res.push_back(line);
    }

    return res;
}


#endif
