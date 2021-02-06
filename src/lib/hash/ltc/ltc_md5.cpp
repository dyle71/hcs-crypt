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
            "ltc-md5",                 // name
            Family::kHash,             // family
            "LibTomCrypt MD5.",        // description (short/left and long/below)

            "This is the MD5 message digest algorithm by Ronald Rivest. Originally intended to be a secure "
            "hash algorithm its weakness has been demonstrated and thus should not be used as a secure hash "
            "algorithm any longer. See: https://en.wikipedia.org/wiki/MD5.",

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


int LTCMD5::Add_(unsigned char const * block_incoming,
                 std::uint64_t size_incoming,
                 unsigned char *,
                 std::uint64_t & size_outgoing) {
    size_outgoing = GetDescription().block_size_outgoing_;
    return md5_process(&GetState(), block_incoming, size_incoming);
}


int LTCMD5::Finalize_(unsigned char * result,
                      std::uint64_t,
                      std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return md5_done(&GetState(), result);
}


Algorithm::Description const & LTCMD5::GetDescription_() const {
    return ::GetDescription();
}


int LTCMD5::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return md5_init(&GetState());
}


void LTCMD5::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<LTCMD5Producer>());
}
