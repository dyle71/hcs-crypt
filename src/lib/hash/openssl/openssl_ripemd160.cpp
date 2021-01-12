/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <openssl/crypto.h>

#include "openssl_ripemd160.hpp"


using namespace headcode::crypt;


/**
 * @brief   The OpenSSL RIPEMD160 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-ripemd160",                // name
            Family::HASH,                       // family
            64ul,                               // input block size
            0ul,                                         // output block size
            20ul,                               // result size
            {0ul, "Not needed.", false},        // initial key
            {0ul, "Not needed.", false},        // final key
            "OpenSSL RIPEMD160.",               // description
            OPENSSL_VERSION_TEXT                // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLRIPEMD160Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLRIPEMD160>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


OpenSSLRIPEMD160::OpenSSLRIPEMD160() {
    RIPEMD160_Init(&ripemd160_ctx_);
}


int OpenSSLRIPEMD160::Add_(char const * block_incoming, std::uint64_t size_incoming) {
    return RIPEMD160_Update(&ripemd160_ctx_, block_incoming, size_incoming) == 1 ? 0 : 1;
}


int OpenSSLRIPEMD160::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(20ul);
    return RIPEMD160_Final(reinterpret_cast<unsigned char *>(result.data()), &ripemd160_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLRIPEMD160::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLRIPEMD160::Initialize_(char const *, std::uint64_t) {
    return RIPEMD160_Init(&ripemd160_ctx_) == 1 ? 0 : 1;
}


void OpenSSLRIPEMD160::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLRIPEMD160Producer>());
}
