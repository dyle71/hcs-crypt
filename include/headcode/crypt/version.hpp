/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_VERSION_HPP
#define HEADCODE_SPACE_CRYPT_VERSION_HPP

#include <cstdint>
#include <string>


#ifndef MAKE_VERSION
#define MAKE_VERSION(x, y, z) ((x) << 24 | (y) << 16 | (z))
#endif


/**
 * @brief   Version check for 1.0.0
 * @return  A value, representing the version.
 */
inline std::uint32_t GetHCSCryptVersion_0_0_1() {
    return MAKE_VERSION(0, 0, 1);
}

/**
 * @brief   The headcode crypt namespace
 */
namespace headcode::crypt {

/**
 * @brief   Returns the current version of the headcode-crypt.
 * @return  A value, representing the current version.
 */
inline std::uint32_t GetCurrentVersion() {
    return GetHCSCryptVersion_0_0_1();
}

/**
 * @brief   Returns a version as string
 * @return  a string holding the current version.
 */
inline std::string GetVersionString() {
    return "0.0.1";
}

}


#endif
