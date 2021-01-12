/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_ripemd160.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt RIPEMD160 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-ripemd160",                             // name
            Family::HASH,                                // family
            {0ul, "Not needed.", false},                 // initial key
            {0ul, "Not needed.", false},                 // final key
            "LibTomCrypt RIPEMD160.",                    // description
            std::string{"libtomcrypt v"} + SCRYPT        // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCRIPEMD160Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCRIPEMD160>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCRIPEMD160::LTCRIPEMD160() {
    rmd160_init(&GetState());
}


int LTCRIPEMD160::Add_(char const * data, std::uint64_t size) {
    return rmd160_process(&GetState(), reinterpret_cast<const unsigned char *>(data), size);
}


int LTCRIPEMD160::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(rmd160_desc.hashsize);
    return rmd160_done(&GetState(), reinterpret_cast<unsigned char *>(result.data()));
}


Algorithm::Description const & LTCRIPEMD160::GetDescription_() const {
    return ::GetDescription();
}


int LTCRIPEMD160::Initialize_(char const *, std::uint64_t) {
    return rmd160_init(&GetState());
}


void LTCRIPEMD160::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCRIPEMD160Producer>());
}
