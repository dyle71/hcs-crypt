/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_128_CBC_ENCRYPTOR_HPP
#define HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_128_CBC_ENCRYPTOR_HPP

#include <cstddef>
#include <vector>

#include <headcode/crypt/algorithm.hpp>

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

    /**
     * @brief   Initialize this object instance.
     * @param   initialization_data     the initial data (== initial key, IV, ...) to use, if any.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data)
    override;
};


}


#endif
