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
            "ltc-sha256",                 // name
            Family::kHash,                // family
            "LibTomCrypt SHA256.",        // description (short/left and long/below)

            "This is the Secure Hash Algorithm 2 variant 256 as defined by the NSA. The SHA-2 family introduced "
            "signifcant changes to SHA-1. See: https://en.wikipedia.org/wiki/SHA-2.",

            std::string{"libtomcrypt v"} + SCRYPT,        // provider
            64ul,                                         // input block size
            ProcessingBlockSize::kEmpty,                  // output block size behaviour
            0ul,                                          // output block size (if changing)
            PaddingStrategy::PADDING_PKCS_5_7,            // default padding strategy
            32ul,                                         // result size
            {},                                           // initial data
            {}                                            // finalization data
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


int LTCSHA256::Add_(unsigned char const * block_incoming,
                    std::uint64_t size_incoming,
                    unsigned char *,
                    std::uint64_t & size_outgoing) {
    size_outgoing = GetDescription().block_size_outgoing_;
    return sha256_process(&GetState(), block_incoming, size_incoming);
}


int LTCSHA256::Finalize_(unsigned char * result,
                         std::uint64_t,
                         std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return sha256_done(&GetState(), result);
}


Algorithm::Description const & LTCSHA256::GetDescription_() const {
    return ::GetDescription();
}


int LTCSHA256::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return sha256_init(&GetState());
}


void LTCSHA256::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCSHA256Producer>());
}
