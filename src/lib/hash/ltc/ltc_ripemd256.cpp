/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_ripemd256.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt RIPEMD256 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-ripemd256",                                     // name
            Family::HASH,                                        // family
            64ul,                                                // input block size
            0ul,                                                 // output block size
            32ul,                                                // result size
            {0ul, "No initial data needed.", false},             // initial data
            {0ul, "No finalization data needed.", false},        // finalization data
            "LibTomCrypt RIPEMD256.",                            // description (short/left and long/below)

            "This is an 265Bit implementation of the RIPE Message Digest. See: https://en.wikipedia.org/wiki/RIPEMD.",

            std::string{"libtomcrypt v"} + SCRYPT        // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCRIPEMD256Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCRIPEMD256>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCRIPEMD256::LTCRIPEMD256() {
    rmd256_init(&GetState());
}


int LTCRIPEMD256::Add_(char const * block_incoming,
                       std::uint64_t size_incoming,
                       char *,
                       std::uint64_t & size_outgoing) {

    size_outgoing = GetDescription().block_size_outgoing_;
    return rmd256_process(&GetState(), reinterpret_cast<const unsigned char *>(block_incoming), size_incoming);
}


int LTCRIPEMD256::Finalize_(char * result, std::uint64_t, char const * , std::uint64_t) {
    return rmd256_done(&GetState(), reinterpret_cast<unsigned char *>(result));
}


Algorithm::Description const & LTCRIPEMD256::GetDescription_() const {
    return ::GetDescription();
}


int LTCRIPEMD256::Initialize_(char const *, std::uint64_t) {
    return rmd256_init(&GetState());
}


void LTCRIPEMD256::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCRIPEMD256Producer>());
}
