/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_tiger192.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt TIGER192 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-tiger192",                 // name
            Family::HASH,                   // family
            "LibTomCrypt TIGER192.",        // description (short/left and long/below)

            "This is the 192 Bit variant of the TIGER hash algorithm created by Ross Anderson and Eli Biham. "
            "See: https://en.wikipedia.org/wiki/Tiger_(hash_function).",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            64ul,                                         // input block size
            0ul,                                          // output block size
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            24ul,                                         // result size
            {},                                           // initial data
            {}                                            // finalization data
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCTIGER192Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCTIGER192>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCTIGER192::LTCTIGER192() {
    tiger_init(&GetState());
}


int LTCTIGER192::Add_(unsigned char const * block_incoming,
                      std::uint64_t size_incoming,
                      unsigned char *,
                      std::uint64_t & size_outgoing) {
    size_outgoing = GetDescription().block_size_outgoing_;
    return tiger_process(&GetState(), block_incoming, size_incoming);
}


int LTCTIGER192::Finalize_(unsigned char * result,
                           std::uint64_t,
                           std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return tiger_done(&GetState(), result);
}


Algorithm::Description const & LTCTIGER192::GetDescription_() const {
    return ::GetDescription();
}


int LTCTIGER192::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return tiger_init(&GetState());
}


void LTCTIGER192::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCTIGER192Producer>());
}
