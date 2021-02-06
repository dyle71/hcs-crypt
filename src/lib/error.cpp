/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <map>

#include <headcode/logger/logger.hpp>
#include <headcode/crypt/error.hpp>


std::string const & headcode::crypt::GetErrorText(headcode::crypt::Error error) {

    static std::map<headcode::crypt::Error, std::string> const known_error_texts = {
            {headcode::crypt::Error::kNoError, "No error"},
            {headcode::crypt::Error::kInvalidArgument, "An argument provided by the user is invalid"},
            {headcode::crypt::Error::kInvalidOperation, "Cannot execute operation in current state"}};

    auto iter = known_error_texts.find(error);
    if (iter == known_error_texts.end()) {
        headcode::logger::Warning{"headcode.crypt"} << "Unknown error code.";
        static std::string const null_string;
        return null_string;
    }

    return iter->second;
}
