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

#include "ltc_aes_256_ecb_encrypter.hpp"

using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt AES 256 ECB algorithm (encryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-aes-256-ecb-encryptor",                                // name
            Family::kSymmetricCipher,                                   // family
            "LibTomCrypt AES 256 in ECB mode (encryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 256 Bit encryption algorithm "
            "in ECB (electronic codebook) mode. Note that ECB bears some weaknesses and should be avoided. "
            "See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard and "
            "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB.",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            16ul,                                         // input block size
            ProcessingBlockSize::kSame,                   // output block size behaviour
            16ul,                                         // output block size (if changing)
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            0ul,                                          // result size

            // initial data
            {{"key", {32ul, PaddingStrategy::PADDING_PKCS_5_7, "A secret shared key.", false}}},

            // finalization data
            {}

    };
    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCAES256ECBEncryptorProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCAES256ECBEncrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int LTCAES256ECBEncrypter::Add_(unsigned char const * block_incoming,
                                std::uint64_t size_incoming,
                                unsigned char * block_outgoing,
                                std::uint64_t & size_outgoing) {

    size_outgoing = size_incoming;

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    symmetric_ECB * state = &GetState();
    return ecb_encrypt(block_incoming, block_outgoing, size_incoming, state);
}


int LTCAES256ECBEncrypter::Finalize_(unsigned char *,
                                     std::uint64_t,
                                     std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return 0;
}


Algorithm::Description const & LTCAES256ECBEncrypter::GetDescription_() const {
    return ::GetDescription();
}


int LTCAES256ECBEncrypter::Initialize_(
        std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data) {

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    auto iter = initialization_data.find("key");
    if (iter == initialization_data.end()) {
        return -1;
    }

    auto [key_data, key_size] = (*iter).second;
    if ((key_size > 0) && (key_data == nullptr)) {
        headcode::logger::Warning{"headcode.crypt"} << "Applying key which is NULL/nullptr while size is > 0.";
        return static_cast<int>(Error::kInvalidArgument);
    }

    symmetric_ECB * state = &GetState();
    return ecb_start(cipher_index, key_data, key_size, 0, state);
}


void LTCAES256ECBEncrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCAES256ECBEncryptorProducer>());
}
