/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>

#include <headcode/crypt/factory.hpp>

#include "ltc_aes_128_ecb_decrypter.hpp"

using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt AES 128 ECB algorithm (decryptor) description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-aes-128-ecb decryptor",                                // name
            Family::SYMMETRIC_CIPHER,                                   // family
            16ul,                                                       // input block size
            16ul,                                                       // output block size
            0ul,                                                        // result size
            {16ul, "A secret shared key.", true},                       // initial data
            {0ul, "No finalization data needed.", false},               // finalization data
            "LibTomCrypt AES 128 in ECB mode (decryptor part).",        // description (short/left and long/below)

            "This is the Advanced Encryption Standard AES (also known as Rijndael) 128 Bit encryption algorithm "
            "in ECB (electronic codebook) mode. Note that ECB bears some weaknesses and should be avoided. "
            "See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard and "
            "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB.",

            std::string{"libtomcrypt v"} + SCRYPT        // provider
    };
    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCAES128ECBDecryptorProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCAES128ECBDecrypter>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int LTCAES128ECBDecrypter::Add_(char const * block_incoming,
                                std::uint64_t size_incoming,
                                char * block_outgoing,
                                std::uint64_t & size_outgoing) {

    size_outgoing = GetDescription().block_size_outgoing_;

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    symmetric_ECB * state = &GetState();
    return ecb_decrypt(reinterpret_cast<unsigned char const *>(block_incoming),
                       reinterpret_cast<unsigned char *>(block_outgoing),
                       size_incoming,
                       state);
}


int LTCAES128ECBDecrypter::Finalize_(char *, std::uint64_t, char const * , std::uint64_t) {
    return 0;
}


Algorithm::Description const & LTCAES128ECBDecrypter::GetDescription_() const {
    return ::GetDescription();
}


int LTCAES128ECBDecrypter::Initialize_(char const * data, std::uint64_t size) {

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    symmetric_ECB * state = &GetState();
    return ecb_start(cipher_index, reinterpret_cast<unsigned char const *>(data), size, 0, state);
}


void LTCAES128ECBDecrypter::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCAES128ECBDecryptorProducer>());
}
