/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_128_ECB_ENCRYPTOR_HPP
#define HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_OPENSSL_AES_128_ECB_ENCRYPTOR_HPP

#include <cstddef>
#include <vector>

#include <headcode/crypt/algorithm.hpp>

#include "openssl_symmetric_cipher.hpp"


namespace headcode::crypt {


/**
 * @brief   The OpenSSL AES 128 Bit Cypher ECB Encryptor.
 */
class OpenSSLAES128ECBEncrypter : public OpenSSLSymmetricCipher {

public:
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
     * @brief   Finalizes this object instance.
     * @param   result          the result of the algorithm.
     * @param   rtesult_size    size of the result for finalization.
     * @param   data            the finalization data (== final key) to use, if any
     * @param   data_size       size of the data used for finalization.
     * @return  0 if finalize was ok, else an error in the context of the concrete algorithm implementation.
     */
    int Finalize_(char * result, std::uint64_t result_size, char const * data, std::uint64_t data_size) override;

    /**
     * @brief   Gets the algorithm description.
     * @return  A string describing the algorithm.
     * */
    Description const & GetDescription_() const override;
};


}


#endif
