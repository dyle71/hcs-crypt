/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_sha1.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt SHA1 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-sha1",                                  // name
            Family::HASH,                                // family
            {0ul, "Not needed.", false},                 // initial key
            {0ul, "Not needed.", false},                 // final key
            "LibTomCrypt SHA1.",                         // description
            std::string{"libtomcrypt v"} + SCRYPT        // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCSHA1Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCSHA1>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCSHA1::LTCSHA1() {
    sha1_init(&GetState());
}


int LTCSHA1::Add_(char const * data, std::uint64_t size) {
    return sha1_process(&GetState(), reinterpret_cast<const unsigned char *>(data), size);
}


int LTCSHA1::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(sha1_desc.hashsize);
    return sha1_done(&GetState(), reinterpret_cast<unsigned char *>(result.data()));
}


Algorithm::Description const & LTCSHA1::GetDescription_() const {
    return ::GetDescription();
}


int LTCSHA1::Initialize_(char const *, std::uint64_t) {
    return sha1_init(&GetState());
}


void LTCSHA1::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCSHA1Producer>());
}
