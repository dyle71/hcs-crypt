/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
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
            "ltc-ripemd320",                                   // name
            Family::HASH,                                // family
            {0ul, "Not needed.", false},                 // initial key
            {0ul, "Not needed.", false},                 // final key
            "LibTomCrypt RIPEMD320.",                          // description
            std::string{"libtomcrypt v"} + SCRYPT        // provider
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


int LTCRIPEMD320::Add_(char const * data, std::uint64_t size) {
    return rmd320_process(&GetState(), reinterpret_cast<const unsigned char *>(data), size);
}


int LTCRIPEMD320::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(rmd320_desc.hashsize);
    return rmd320_done(&GetState(), reinterpret_cast<unsigned char *>(result.data()));
}


Algorithm::Description const & LTCRIPEMD320::GetDescription_() const {
    return ::GetDescription();
}


int LTCRIPEMD320::Initialize_(char const *, std::uint64_t) {
    return rmd320_init(&GetState());
}


void LTCRIPEMD320::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCRIPEMD320Producer>());
}
