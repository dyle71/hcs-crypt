/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <openssl/opensslv.h>

#include <headcode/crypt/factory.hpp>

#include "openssl_aes_128_cbc_decryptor.hpp"

using namespace headcode::crypt;


/**
 * @brief   The OpenSSL AES 128 CBC algorithm (decryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-aes-128-cbc-decryptor",                        // name
            Family::kSymmetricCipher,                               // family
            "OpenSSL AES 128 in CBC mode (decryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 128 Bit encryption algorithm "
            "in CBC (cipher block chaining) mode. See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard "
            "and https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC).",

            OPENSSL_VERSION_TEXT,                     // provider
            16ul,                                     // input block size
            ProcessingBlockSize::kSame,               // output block size behaviour
            16ul,                                     // output block size (if changing)
            PaddingStrategy::PADDING_PKCS_5_7,        // default padding strategy
            0ul,                                      // result size

            // initial data
            {{"key", {16ul, PaddingStrategy::PADDING_PKCS_5_7, "A secret shared key.", false}},
             {"iv", {16ul, PaddingStrategy::PADDING_PKCS_5_7, "An initialization vector.", false}}},

            // finalization data
            {}};

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLAES128CBCDecrypterProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLAES128CBCDecrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


EVP_CIPHER const * OpenSSLAES128CBCDecrypter::GetCipher() const {
    return EVP_aes_128_cbc();
}


Algorithm::Description const & OpenSSLAES128CBCDecrypter::GetDescription_() const {
    return ::GetDescription();
}


void OpenSSLAES128CBCDecrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLAES128CBCDecrypterProducer>());
}
