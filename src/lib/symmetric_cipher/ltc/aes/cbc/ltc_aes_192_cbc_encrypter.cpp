/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/logger/logger.hpp>
#include <headcode/crypt/error.hpp>
#include <headcode/crypt/factory.hpp>

#include "ltc_aes_192_cbc_encrypter.hpp"

using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt AES 192 CBC algorithm (encryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-aes-192-cbc-encryptor",                                // name
            Family::kSymmetricCipher,                                   // family
            "LibTomCrypt AES 192 in CBC mode (encryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 192 Bit encryption algorithm "
            "in CBC (cipher block chaining) mode. See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard "
            "and https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC).",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            16ul,                                         // input block size
            16ul,                                         // output block size
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            0ul,                                          // result size

            // initial data
            {{"key", {24ul, PaddingStrategy::PADDING_PKCS_5_7, "A secret shared key.", false}},
             {"iv", {16ul, PaddingStrategy::PADDING_PKCS_5_7, "An initialization vector.", false}}},

            // finalization data
            {}

    };
    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCAES192CBCEncryptorProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCAES192CBCEncrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int LTCAES192CBCEncrypter::Add_(unsigned char const * block_incoming,
                                std::uint64_t size_incoming,
                                unsigned char * block_outgoing,
                                std::uint64_t & size_outgoing) {

    size_outgoing = GetDescription().block_size_outgoing_;

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return static_cast<int>(Error::kInvalidOperation);
    }

    symmetric_CBC * state = &GetState();
    return cbc_encrypt(block_incoming, block_outgoing, size_incoming, state);
}


int LTCAES192CBCEncrypter::Finalize_(unsigned char *,
                                     std::uint64_t,
                                     std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return 0;
}


Algorithm::Description const & LTCAES192CBCEncrypter::GetDescription_() const {
    return ::GetDescription();
}


int LTCAES192CBCEncrypter::Initialize_(
        std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data) {

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return static_cast<int>(Error::kInvalidArgument);
    }

    auto iter = initialization_data.find("key");
    if (iter == initialization_data.end()) {
        return static_cast<int>(Error::kInvalidArgument);
    }
    auto [key_data, key_size] = (*iter).second;
    if ((key_size > 0) && (key_data == nullptr)) {
        headcode::logger::Warning{"headcode.crypt"} << "Applying key which is NULL/nullptr while size is > 0.";
        return static_cast<int>(Error::kInvalidArgument);
    }

    iter = initialization_data.find("iv");
    if (iter == initialization_data.end()) {
        return static_cast<int>(Error::kInvalidArgument);
    }
    auto [iv_data, iv_size] = (*iter).second;
    if ((iv_size > 0) && (iv_data == nullptr)) {
        headcode::logger::Warning{"headcode.crypt"} << "Applying IV which is NULL/nullptr while size is > 0.";
        return static_cast<int>(Error::kInvalidArgument);
    }

    symmetric_CBC * state = &GetState();
    return cbc_start(cipher_index, iv_data, key_data, key_size, 0, state);
}


void LTCAES192CBCEncrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCAES192CBCEncryptorProducer>());
}
