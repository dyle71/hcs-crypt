/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_FAMILY_HPP
#define HEADCODE_SPACE_CRYPT_FAMILY_HPP


namespace headcode::crypt {


/**
 * @brief   The Algorithm class is the abstract class for any crypto-algorithm.
 */
enum class Family {
    CYPHER_SYMMETRIC = 0x0000,        //!< @brief An symmetric algorithm used to encrypt and/or decrypt data.
    HASH = 0x1000,                    //!< @brief An algorithm which produces hashsums of data.
    UNKNOWN = 0xffff                  //!< @brief An unknown or error like family.
};


}


#endif
