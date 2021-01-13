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

#include "openssl_aes_128_ecb_encryptor.hpp"

using namespace headcode::crypt;


/**
 * @brief   The OpenSSL AES 128 ECB algorithm (encryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-aes-128-ecb encryptor",                            // name
            Family::SYMMETRIC_CIPHER,                                   // family
            16ul,                                                       // input block size
            16ul,                                                       // output block size
            0ul,                                                        // result size
            {16ul, "A secret shared key.", true},                       // initial data
            {0ul, "No finalization data needed.", false},               // finalization data
            "LibTomCrypt AES 128 in ECB mode (encryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 128 Bit encryption algorithm "
            "in ECB (electronic codebook) mode. Note that ECB bears some weaknesses and should be avoided. "
            "See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard and "
            "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB.",

            OPENSSL_VERSION_TEXT        // provider
    };
    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLAES128ECBEncryptorProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLAES128ECBEncrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int OpenSSLAES128ECBEncrypter::Finalize_(char * result, std::uint64_t, char const * , std::uint64_t) {
    return 0;
}


EVP_CIPHER const * OpenSSLAES128ECBEncrypter::GetCipher() const {
    return EVP_aes_128_ecb();
}


Algorithm::Description const & OpenSSLAES128ECBEncrypter::GetDescription_() const {
    return ::GetDescription();
}


void OpenSSLAES128ECBEncrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLAES128ECBEncryptorProducer>());
}
