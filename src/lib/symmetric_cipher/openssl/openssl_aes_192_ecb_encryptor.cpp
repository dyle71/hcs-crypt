/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>

#include <openssl/opensslv.h>

#include <headcode/crypt/factory.hpp>

#include "openssl_aes_192_ecb_encryptor.hpp"

using namespace headcode::crypt;


/**
 * @brief   The OpenSSL AES 192 ECB algorithm (encryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-aes-192-ecb encryptor",                        // name
            Family::SYMMETRIC_CIPHER,                               // family
            "OpenSSL AES 192 in ECB mode (encryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 192 Bit encryption algorithm "
            "in ECB (electronic codebook) mode. Note that ECB bears some weaknesses and should be avoided. "
            "See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard and "
            "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB.",

            OPENSSL_VERSION_TEXT,                     // provider
            24ul,                                     // input block size
            24ul,                                     // output block size
            PaddingStrategy::PADDING_PKCS_5_7,        // default padding strategy
            0ul,                                      // result size

            // initial data
            {{"key", {24ul, PaddingStrategy::PADDING_PKCS_5_7, "A secret shared key.", false}}},

            // finalization data
            {}
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLAES192ECBEncrypterProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLAES192ECBEncrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int OpenSSLAES192ECBEncrypter::Initialize_(const std::map<std::string, std::tuple<const unsigned char *, std::uint64_t>> & initialization_data) {
    // TODO
}


EVP_CIPHER const * OpenSSLAES192ECBEncrypter::GetCipher() const {
    return EVP_aes_192_ecb();
}


Algorithm::Description const & OpenSSLAES192ECBEncrypter::GetDescription_() const {
    return ::GetDescription();
}


void OpenSSLAES192ECBEncrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLAES192ECBEncrypterProducer>());
}
