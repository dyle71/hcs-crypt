/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_LTC_SYMMETRIC_CBC_CIPHER_HPP
#define HEADCODE_SPACE_CRYPT_HASH_LTC_SYMMETRIC_CBC_CIPHER_HPP

#include <tomcrypt.h>

#include <headcode/crypt/algorithm.hpp>

#include "symmetric_cipher/ltc/ltc_symmetric_cipher.hpp"


namespace headcode::crypt {


/**
 * @brief   Base class of all LibTomCrypt symmetric cipher algorithms running in CBC mode.
 */
class LTCSymmetricCBCCipher : public LTCSymmetricCipher {

    symmetric_CBC state_;        //!< @brief The LibTomCrypt CBC state structure used.

protected:
    /**
     * @brief   Gets the symmetric CBC state used.
     * @return  The symmetric CBC state.
     */
    symmetric_CBC & GetState() {
        return state_;
    }

    /**
     * @brief   Gets the symmetric CBC state used.
     * @return  The symmetric CBC state.
     */
    symmetric_CBC const & GetState() const {
        return state_;
    }
};


}


#endif
