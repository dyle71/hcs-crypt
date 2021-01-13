/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_192_ECB_DECRYPTOR_HPP
#define HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_192_ECB_DECRYPTOR_HPP

#include <cstddef>
#include <vector>

#include <headcode/crypt/algorithm.hpp>

#include "openssl_symmetric_cipher.hpp"


namespace headcode::crypt {


/**
 * @brief   The OpenSSL AES 192 Bit Cypher ECB Decryptor.
 */
class OpenSSLAES192ECBDecrypter : public OpenSSLSymmetricCipher {

public:
    /**
     * @brief   Constructor
     */
    OpenSSLAES192ECBDecrypter() : OpenSSLSymmetricCipher(false) {
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
