/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_TEST_SHARED_TRIM_STRING_HPP
#define HEADCODE_SPACE_CRYPT_TEST_SHARED_TRIM_STRING_HPP

#include <regex>
#include <string>


/**
 * @brief   Strips all whitespace from start and end of a string.
 * @param   str     the string to strip
 * @return  same as str but all whitespaces removed.
 */
static std::string Trim(std::string str) {

    static std::regex const re{R"(\s*(.*)\s*)"};
    std::smatch m;
    if (std::regex_match(str, m, re)) {
        str = m[1].str();
    }
    return str;
}


#endif
