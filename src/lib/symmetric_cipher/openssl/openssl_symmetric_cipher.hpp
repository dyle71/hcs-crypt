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
     * @param   block_incoming      incoming data block to add.
     * @param   size_incoming       size of the incoming data to add.
     * @param   block_outgoing      outgoing data block.
     * @param   size_outgoing       size of the outgoing data block (will be adjusted).
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Add_(unsigned char const * block_incoming,
             std::uint64_t size_incoming,
             unsigned char * block_outgoing,
             std::uint64_t & size_outgoing) override;

    /**
     * @brief   Finalizes this object instance.
     * @param   result                  the result of the algorithm.
     * @param   result_size             size of the result for finalization.
     * @param   finalization_data       the final data (== final key) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Finalize_(
            unsigned char * result,
            std::uint64_t result_size,
            std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & finalization_data) override;

    /**
     * @brief   Initialize this object instance.
     * @param   initialization_data     the initial data (== initial key, IV, ...) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data)
            override;

    /**
     * @brief   Verifies the existance and validity of an initit data element.
     * @param   data                    this will receive the deduced value.
     * @param   initialization_data     the set of init data elements.
     * @param   name                    the name of the init data element to search for.
     * @param   EVP_GET_LENGTH          the OpenSSL function returning the length needed.
     * @return  true, if the value is usable.
     */
    bool VerifyInitValue(
            unsigned char const *& data,
            const std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> & initialization_data,
            std::string const & name,
            int (*EVP_GET_LENGTH)(EVP_CIPHER_CTX const *)) const;
};


}


#endif
