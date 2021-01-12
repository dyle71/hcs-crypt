/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_LTC_SYMMETRIC_CIPHER_HPP
#define HEADCODE_SPACE_CRYPT_HASH_LTC_SYMMETRIC_CIPHER_HPP

#include <tomcrypt.h>

#include <headcode/crypt/algorithm.hpp>


namespace headcode::crypt {


/**
 * @brief   Base class of all LibTomCrypt symmetric cipher algorithms.
 */
class LTCSymmetricCipher : public Algorithm {

    ltc_cipher_descriptor const * descriptor_{nullptr};        //!< @brief The LibTomCrypt descriptior for the cipher.

public:
    /**
     * @brief  Destructor.
     */
    ~LTCSymmetricCipher() noexcept override;

protected:
    /**
     * @brief   Returns the LibTomCrypt descriptor for the current cipher.
     * @return  The loaded LibTomCrypt descriptor.
     */
    ltc_cipher_descriptor const * GetDescriptor() const {
        return descriptor_;
    }

    /**
     * @brief   Sets and registers the cipher descriptor.
     * @param   descriptor      The new cipher descriptor.
     * @return  The index into the cipher_descriptor table (or -1 in case of error).
     */
    int SetDescriptor(ltc_cipher_descriptor const * descriptor);
};


}


#endif
