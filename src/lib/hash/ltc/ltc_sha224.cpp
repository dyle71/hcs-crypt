/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_sha224.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt SHA224 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-sha224",                                        // name
            Family::HASH,                                        // family
            64ul,                                                // input block size
            0ul,                                                 // output block size
            28ul,                                                // result size
            {0ul, "No initial data needed.", false},             // initial data
            {0ul, "No finalization data needed.", false},        // finalization data
            "LibTomCrypt SHA224.",                               // description (short/left and long/below)

            "This is the Secure Hash Algorithm 2 variant 224 as defined by the NSA. The SHA-2 family introduced "
            "signifcant changes to SHA-1. See: https://en.wikipedia.org/wiki/SHA-2.",

            std::string{"libtomcrypt v"} + SCRYPT        // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCSHA224Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCSHA224>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCSHA224::LTCSHA224() {
    sha224_init(&GetState());
}


int LTCSHA224::Add_(char const * block_incoming, std::uint64_t size_incoming, char *, std::uint64_t & size_outgoing) {
    size_outgoing = GetDescription().block_size_outgoing_;
    return sha224_process(&GetState(), reinterpret_cast<const unsigned char *>(block_incoming), size_incoming);
}


int LTCSHA224::Finalize_(char * result, std::uint64_t, char const * , std::uint64_t) {
    return sha224_done(&GetState(), reinterpret_cast<unsigned char *>(result));
}


Algorithm::Description const & LTCSHA224::GetDescription_() const {
    return ::GetDescription();
}


int LTCSHA224::Initialize_(char const *, std::uint64_t) {
    return sha224_init(&GetState());
}


void LTCSHA224::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCSHA224Producer>());
}
