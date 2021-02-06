/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_ripemd128.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt RIPEMD128 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-ripemd128",                 // name
            Family::kHash,                   // family
            "LibTomCrypt RIPEMD128.",        // description (short/left and long/below)

            "This is an 128Bit implementation of the RIPE Message Digest. This 128Bit variant is not "
            "considered secure. See: https://en.wikipedia.org/wiki/RIPEMD.",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            64ul,                                         // input block size
            0ul,                                          // output block size
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            16ul,                                         // result size
            {},                                           // initial data
            {}                                            // finalization data
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCRIPEMD128Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCRIPEMD128>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCRIPEMD128::LTCRIPEMD128() {
    rmd128_init(&GetState());
}


int LTCRIPEMD128::Add_(unsigned char const * block_incoming,
                       std::uint64_t size_incoming,
                       unsigned char *,
                       std::uint64_t & size_outgoing) {

    size_outgoing = GetDescription().block_size_outgoing_;
    return rmd128_process(&GetState(), block_incoming, size_incoming);
}


int LTCRIPEMD128::Finalize_(unsigned char * result,
                            std::uint64_t,
                            std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return rmd128_done(&GetState(), result);
}


Algorithm::Description const & LTCRIPEMD128::GetDescription_() const {
    return ::GetDescription();
}


int LTCRIPEMD128::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return rmd128_init(&GetState());
}


void LTCRIPEMD128::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCRIPEMD128Producer>());
}
