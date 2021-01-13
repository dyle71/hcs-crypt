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
     * @brief   Constructor
     * @param   encrypt         enrypt or decrypt instance.
     */
    explicit OpenSSLSymmetricCipher(bool encrypt = true);

    /**
     * @brief  Destructor.
     */
    ~OpenSSLSymmetricCipher() noexcept override;

protected:
    /**
     * @brief   Gets the OpenSSL cipher to work on.
     * @return  The OpenSSL cipher to use.
     */
    virtual EVP_CIPHER const * GetCipher() const = 0;

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

private:
    /**
     * @brief   Adds data to the algorithm
     * @param   block_incoming      the incoming data to add.
     * @param   size_incoming       size of the incoming data to add.
     * @param   block_outgoing      outgoing data block.
     * @param   size_outgoing       size of the outgoing data block (will be adjusted).
     * @return  0 if add was ok, else an error.
     */
    int Add_(char const * block_incoming,
             std::uint64_t size_incoming,
             char * block_outgoing,
             std::uint64_t & size_outgoing) override;


    /**
     * @brief   Initialize this object instance.
     * This always returns 0.
     * @param   data        the initial data (== initial key) to use, if any
     * @param   size        size of the data used for initialization.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize_(char const * data, std::uint64_t size) override;
};


}


#endif
