/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <openssl/crypto.h>

#include "openssl_md5.hpp"


using namespace headcode::crypt;


/**
 * @brief   The OpenSSL MD5 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-md5",                      // name
            Family::HASH,                       // family
            64ul,                               // input block size
            0ul,                                         // output block size
            16ul,                               // result size
            {0ul, "Not needed.", false},        // initial key
            {0ul, "Not needed.", false},        // final key
            "OpenSSL MD5.",                     // description
            OPENSSL_VERSION_TEXT                // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLMD5Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLMD5>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


OpenSSLMD5::OpenSSLMD5() {
    MD5_Init(&md5_ctx_);
}


int OpenSSLMD5::Add_(char const * data, std::uint64_t size) {
    return MD5_Update(&md5_ctx_, data, size) == 1 ? 0 : 1;
}


int OpenSSLMD5::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(16ul);
    return MD5_Final(reinterpret_cast<unsigned char *>(result.data()), &md5_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLMD5::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLMD5::Initialize_(char const *, std::uint64_t) {
    return MD5_Init(&md5_ctx_) == 1 ? 0 : 1;
}


void OpenSSLMD5::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLMD5Producer>());
}
