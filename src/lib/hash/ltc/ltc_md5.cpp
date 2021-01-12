/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <tomcrypt.h>

#include "ltc_md5.hpp"


using namespace headcode::crypt;


/**
 * @brief   The LibTomCrypt MD5 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "ltc-md5",                                   // name
            Family::HASH,                                // family
            {0ul, "Not needed.", false},                 // initial key
            {0ul, "Not needed.", false},                 // final key
            "LibTomCrypt MD5.",                          // description
            std::string{"libtomcrypt v"} + SCRYPT        // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class LTCMD5Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<LTCMD5>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


LTCMD5::LTCMD5() {
    md5_init(&GetState());
}


int LTCMD5::Add_(char const * data, std::uint64_t size) {
    return md5_process(&GetState(), reinterpret_cast<const unsigned char *>(data), size);
}


int LTCMD5::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(md5_desc.hashsize);
    return md5_done(&GetState(), reinterpret_cast<unsigned char *>(result.data()));
}


Algorithm::Description const & LTCMD5::GetDescription_() const {
    return ::GetDescription();
}


int LTCMD5::Initialize_(char const *, std::uint64_t) {
    return md5_init(&GetState());
}


void LTCMD5::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCMD5Producer>());
}
