/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_LTC_HASH_HPP
#define HEADCODE_SPACE_CRYPT_HASH_LTC_HASH_HPP

#include <tomcrypt.h>

#include <headcode/crypt/algorithm.hpp>


namespace headcode::crypt {


/**
 * @brief   Base class of all LibTomCrypt hash algorithms.
 */
class LTCHash : public Algorithm {

    hash_state state_;        //!< @brief The inner hash state.

protected:

    /**
     * @brief   Gets the inner LTC hash state.
     * @return  The current LTC hash state.
     */
    hash_state & GetState() {
        return state_;
    }

    /**
     * @brief   Gets the inner LTC hash state.
     * @return  The current LTC hash state.
     */
    hash_state const & GetState() const {
        return state_;
    }
};


}


#endif
