/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <openssl/opensslv.h>

#include <headcode/crypt/factory.hpp>

#include "openssl_aes_256_cbc_decryptor.hpp"

using namespace headcode::crypt;


/**
 * @brief   The OpenSSL AES 256 CBC algorithm (decryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-aes-256-cbc-decryptor",                        // name
            Family::kSymmetricCipher,                               // family
            "OpenSSL AES 256 in CBC mode (decryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 256 Bit encryption algorithm "
            "in CBC (cipher block chaining) mode. See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard "
            "and https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC).",

            OPENSSL_VERSION_TEXT,                     // provider
            16ul,                                     // input block size
            16ul,                                     // output block size
            PaddingStrategy::PADDING_PKCS_5_7,        // default padding strategy
            0ul,                                      // result size

            // initial data
            {{"key", {32ul, PaddingStrategy::PADDING_PKCS_5_7, "A secret shared key.", false}},
             {"iv", {16ul, PaddingStrategy::PADDING_PKCS_5_7, "An initialization vector.", false}}},

            // finalization data
            {}};

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLAES256CBCDecrypterProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLAES256CBCDecrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


EVP_CIPHER const * OpenSSLAES256CBCDecrypter::GetCipher() const {
    return EVP_aes_256_cbc();
}


Algorithm::Description const & OpenSSLAES256CBCDecrypter::GetDescription_() const {
    return ::GetDescription();
}


void OpenSSLAES256CBCDecrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLAES256CBCDecrypterProducer>());
}
