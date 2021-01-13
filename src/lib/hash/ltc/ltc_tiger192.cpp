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
            "ltc-tiger192",                                      // name
            Family::HASH,                                        // family
            64ul,                                                // input block size
            0ul,                                                 // output block size
            24ul,                                                // result size
            {0ul, "No initial data needed.", false},             // initial data
            {0ul, "No finalization data needed.", false},        // finalization data
            "LibTomCrypt TIGER192.",                             // description
            std::string{"libtomcrypt v"} + SCRYPT                // provider
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


int LTCTIGER192::Add_(char const * block_incoming, std::uint64_t size_incoming, char *, std::uint64_t & size_outgoing) {
    size_outgoing = GetDescription().block_size_outgoing_;
    return tiger_process(&GetState(), reinterpret_cast<const unsigned char *>(block_incoming), size_incoming);
}


int LTCTIGER192::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(tiger_desc.hashsize);
    return tiger_done(&GetState(), reinterpret_cast<unsigned char *>(result.data()));
}


Algorithm::Description const & LTCTIGER192::GetDescription_() const {
    return ::GetDescription();
}


int LTCTIGER192::Initialize_(char const *, std::uint64_t) {
    return tiger_init(&GetState());
}


void LTCTIGER192::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCTIGER192Producer>());
}
