/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_LTC_SYMMETRIC_ECB_CIPHER_HPP
#define HEADCODE_SPACE_CRYPT_HASH_LTC_SYMMETRIC_ECB_CIPHER_HPP

#include <tomcrypt.h>

#include <headcode/crypt/algorithm.hpp>

#include "ltc_symmetric_cipher.hpp"


namespace headcode::crypt {


/**
 * @brief   Base class of all LibTomCrypt symmetric cipher algorithms running in ECB mode.
 */
class LTCSymmetricECBCipher : public LTCSymmetricCipher {

    symmetric_ECB state_;        //!< @brief The LibTomCrypt ECB state structure used.

protected:
    /**
     * @brief   Gets the symmetric ECB state used.
     * @return  The symmetric ECB state.
     */
    symmetric_ECB & GetState() {
        return state_;
    }

    /**
     * @brief   Gets the symmetric ECB state used.
     * @return  The symmetric ECB state.
     */
    symmetric_ECB const & GetState() const {
        return state_;
    }
};


}


#endif
