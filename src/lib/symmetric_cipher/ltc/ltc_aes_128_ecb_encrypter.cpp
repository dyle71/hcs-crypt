/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>

#include <headcode/crypt/factory.hpp>

#include "ltc_aes_128_ecb_encrypter.hpp"

using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt AES 128 ECB algorithm (encryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-aes-128-ecb-encryptor",                                // name
            Family::SYMMETRIC_CIPHER,                                   // family
            "LibTomCrypt AES 128 in ECB mode (encryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 128 Bit encryption algorithm "
            "in ECB (electronic codebook) mode. Note that ECB bears some weaknesses and should be avoided. "
            "See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard and "
            "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB.",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            16ul,                                         // input block size
            16ul,                                         // output block size
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            0ul,                                          // result size

            // initial data
            {{"key", {16ul, PaddingStrategy::PADDING_PKCS_5_7, "A secret shared key.", false}}},

            // finalization data
            {}

    };
    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCAES128ECBEncryptorProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCAES128ECBEncrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int LTCAES128ECBEncrypter::Add_(unsigned char const * block_incoming,
                                std::uint64_t size_incoming,
                                unsigned char * block_outgoing,
                                std::uint64_t & size_outgoing) {

    size_outgoing = GetDescription().block_size_outgoing_;

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    symmetric_ECB * state = &GetState();
    return ecb_encrypt(block_incoming, block_outgoing, size_incoming, state);
}


int LTCAES128ECBEncrypter::Finalize_(unsigned char *,
                                     std::uint64_t,
                                     std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return 0;
}


Algorithm::Description const & LTCAES128ECBEncrypter::GetDescription_() const {
    return ::GetDescription();
}


int LTCAES128ECBEncrypter::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data) {

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    auto iter = initialization_data.find("key");
    if (iter == initialization_data.end()) {
        return -1;
    }

    auto [key_data, key_size] = (*iter).second;
    if (key_size > 0) {
        assert(key_data != nullptr && "Applying key which is NULL/nullptr while size is > 0.");
    }

    symmetric_ECB * state = &GetState();
    return ecb_start(cipher_index, key_data, key_size, 0, state);
}


void LTCAES128ECBEncrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCAES128ECBEncryptorProducer>());
}
