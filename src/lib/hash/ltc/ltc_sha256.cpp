/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_sha256.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt SHA256 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-sha256",                                // name
            Family::HASH,                                // family
            64ul,                                        // input block size
            32ul,                                        // output block size
            {0ul, "Not needed.", false},                 // initial key
            {0ul, "Not needed.", false},                 // final key
            "LibTomCrypt SHA256.",                       // description
            std::string{"libtomcrypt v"} + SCRYPT        // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCSHA256Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCSHA256>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCSHA256::LTCSHA256() {
    sha256_init(&GetState());
}


int LTCSHA256::Add_(char const * data, std::uint64_t size) {
    return sha256_process(&GetState(), reinterpret_cast<const unsigned char *>(data), size);
}


int LTCSHA256::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(sha256_desc.hashsize);
    return sha256_done(&GetState(), reinterpret_cast<unsigned char *>(result.data()));
}


Algorithm::Description const & LTCSHA256::GetDescription_() const {
    return ::GetDescription();
}


int LTCSHA256::Initialize_(char const *, std::uint64_t) {
    return sha256_init(&GetState());
}


void LTCSHA256::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCSHA256Producer>());
}
