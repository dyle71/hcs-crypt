/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_ERROR_HPP
#define HEADCODE_SPACE_CRYPT_ERROR_HPP

#include <string>


namespace headcode::crypt {


/**
 * @brief   Different errors the framework will report.
 */
enum class Error {
    kNoError = 0,                 //!< @brief No error occurred, all good.
    kInvalidArgument = -1,        //!< @brief An argument provided by the user is invalid/unexpected.
    kInvalidOperation = -2        //!< @brief An operation is invalid (target object is not in propber state).
};


/**
 * @brief   Returns a human readable text for the error.
 * @return  A text describing the error.
 */
std::string const & GetErrorText(Error error);

}


#endif
