/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_ripemd320.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt RIPEMD320 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-ripemd320",                 // name
            Family::kHash,                   // family
            "LibTomCrypt RIPEMD320.",        // description (short/left and long/below)

            "This is an 360Bit implementation of the RIPE Message Digest. See: https://en.wikipedia.org/wiki/RIPEMD.",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            64ul,                                         // input block size
            ProcessingBlockSize::kEmpty,                  // output block size behaviour
            0ul,                                          // output block size (if changing)
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            40ul,                                         // result size
            {},                                           // initial data
            {}                                            // finalization data
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCRIPEMD320Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCRIPEMD320>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCRIPEMD320::LTCRIPEMD320() {
    rmd320_init(&GetState());
}


int LTCRIPEMD320::Add_(unsigned char const * block_incoming,
                       std::uint64_t size_incoming,
                       unsigned char *,
                       std::uint64_t & size_outgoing) {

    size_outgoing = GetDescription().block_size_outgoing_;
    return rmd320_process(&GetState(), block_incoming, size_incoming);
}


int LTCRIPEMD320::Finalize_(unsigned char * result,
                            std::uint64_t,
                            std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return rmd320_done(&GetState(), result);
}


Algorithm::Description const & LTCRIPEMD320::GetDescription_() const {
    return ::GetDescription();
}


int LTCRIPEMD320::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return rmd320_init(&GetState());
}


void LTCRIPEMD320::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCRIPEMD320Producer>());
}
