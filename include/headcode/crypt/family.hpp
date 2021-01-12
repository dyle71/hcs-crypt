/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_FAMILY_HPP
#define HEADCODE_SPACE_CRYPT_FAMILY_HPP

#include <string>

namespace headcode::crypt {


/**
 * @brief   Different types of algorithms we know of.
 */
enum class Family {
    SYMMETRIC_CIPHER = 0x0000,        //!< @brief An symmetric algorithm used to encrypt and/or decrypt data.
    HASH = 0x1000,                    //!< @brief An algorithm which produces hash-sums of data.
    UNKNOWN = 0xffff                  //!< @brief An unknown or error like family.
};


/**
 * @brief   Returns a human readable text for a crypto family.
 * @return  A text describing the crypto family.
 */
std::string const & GetFamilyText(Family family);

}


#endif
