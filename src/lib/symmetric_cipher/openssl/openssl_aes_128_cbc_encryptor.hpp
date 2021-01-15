/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_128_CBC_ENCRYPTOR_HPP
#define HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_128_CBC_ENCRYPTOR_HPP

#include "openssl_symmetric_cipher.hpp"


namespace headcode::crypt {


/**
 * @brief   The OpenSSL AES 128 Bit Cypher CBC Encryptor.
 */
class OpenSSLAES128CBCEncrypter : public OpenSSLSymmetricCipher {

public:
    /**
     * @brief   Constructor
     */
    OpenSSLAES128CBCEncrypter() : OpenSSLSymmetricCipher(true) {
    }

    /**
     * @brief   Register this class of algorithms.
     */
    static void Register();

protected:
    /**
     * @brief   Gets the OpenSSL cipher to work on.
     * @return  The OpenSSL cipher to use.
     */
    EVP_CIPHER const * GetCipher() const override;

private:
    /**
     * @brief   Gets the algorithm description.
     * @return  A string describing the algorithm.
     * */
    Description const & GetDescription_() const override;
};


}


#endif
