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

#include "ltc_aes_128_cbc_decrypter.hpp"

using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt AES 128 CBC algorithm (decryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-aes-128-cbc-decryptor",                                // name
            Family::kSymmetricCipher,                                   // family
            "LibTomCrypt AES 128 in CBC mode (decryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 128 Bit encryption algorithm "
            "in CBC (cipher block chaining) mode. See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard "
            "and https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC).",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            16ul,                                         // input block size
            16ul,                                         // output block size
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            0ul,                                          // result size

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
class LTCAES128CBCDecryptorProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCAES128CBCDecrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int LTCAES128CBCDecrypter::Add_(unsigned char const * block_incoming,
                                std::uint64_t size_incoming,
                                unsigned char * block_outgoing,
                                std::uint64_t & size_outgoing) {

    size_outgoing = GetDescription().block_size_outgoing_;

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return static_cast<int>(Error::kInvalidOperation);
    }

    symmetric_CBC * state = &GetState();
    return cbc_decrypt(block_incoming, block_outgoing, size_incoming, state);
}


int LTCAES128CBCDecrypter::Finalize_(unsigned char *,
                                     std::uint64_t,
                                     std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return 0;
}


Algorithm::Description const & LTCAES128CBCDecrypter::GetDescription_() const {
    return ::GetDescription();
}


int LTCAES128CBCDecrypter::Initialize_(
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


void LTCAES128CBCDecrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCAES128CBCDecryptorProducer>());
}
