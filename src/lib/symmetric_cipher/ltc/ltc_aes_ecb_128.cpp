/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>

#include <headcode/crypt/factory.hpp>

#include "ltc_aes_ecb_128.hpp"

using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt AES 128 ECB algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static std::string const INPUT_ARGUMENT_DESCRIPTION = "The input argument only contains the key as binary.";

    static Algorithm::Description description = {
            "ltc-aes-ecb-128",                               // name
            Family::SYMMETRIC_CIPHER,                        // family
            16ul,                                            // input block size
            16ul,                                            // output block size
            0ul,                                             // result size
            {16ul, INPUT_ARGUMENT_DESCRIPTION, true},        // initial key
            {0ul, "Not needed.", false},                     // final key
            "LibTomCrypt AES 128 in ECB mode.",              // description
            std::string{"libtomcrypt v"} + SCRYPT            // provider
    };
    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCAESECB128Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCAESECB128>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int LTCAESECB128::Add_(char const * data, std::uint64_t size) {

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    return 0;
}


int LTCAESECB128::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    return 0;
}


Algorithm::Description const & LTCAESECB128::GetDescription_() const {
    return ::GetDescription();
}


int LTCAESECB128::Initialize_(char const * data, std::uint64_t size) {

    auto cipher_index = SetDescriptor(&aes_desc);
    if (cipher_index == -1) {
        return -1;
    }

    symmetric_ECB * state = &GetState();
    return ecb_start(cipher_index, reinterpret_cast<unsigned char const *>(data), size, 0, state);
}


void LTCAESECB128::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCAESECB128Producer>());
}
