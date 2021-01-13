/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_OPENSSL_SYMMETRIC_CIPHER_HPP
#define HEADCODE_SPACE_CRYPT_HASH_OPENSSL_SYMMETRIC_CIPHER_HPP

#include <openssl/evp.h>

#include <headcode/crypt/algorithm.hpp>


namespace headcode::crypt {


/**
 * @brief   Base class of all OpenSSL symmetric cipher algorithms.
 */
class OpenSSLSymmetricCipher : public Algorithm {

    EVP_CIPHER_CTX * ctx_{nullptr};        //!< @brief OpenSSL cipher context.
    bool encrypt_{true};                   //!< @brief Encrypt or Decrypt instance.

public:
    /**
     * @brief Constructor
     * @param   encrypt         enrypt or decrypt instance.
     */
    explicit OpenSSLSymmetricCipher(bool encrypt = true);

    /**
     * @brief  Destructor.
     */
    ~OpenSSLSymmetricCipher() noexcept override;

protected:
    /**
     * @brief   Returns the included OpenSSL cipher context.
     * @return  The OpenSSL cipher context.
     */
    EVP_CIPHER_CTX * GetCipherContext() {
        return ctx_;
    }

    /**
     * @brief   Returns the included OpenSSL cipher context.
     * @return  The OpenSSL cipher context.
     */
    EVP_CIPHER_CTX const * GetCipherContext() const {
        return ctx_;
    }

    /**
     * @brief   Checks if this is an encryptor instance.
     * @return  true, it this is an encryptor instance.
     */
    bool IsEncryptor() const {
        return encrypt_;
    }
};


}


#endif
