/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <openssl/crypto.h>

#include "openssl_sha1.hpp"


using namespace headcode::crypt;


/**
 * @brief   The OpenSSL SHA1 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-sha1",                     // name
            Family::HASH,                       // family
            64ul,                               // input block size
            20ul,                               // output block size
            {0ul, "Not needed.", false},        // initial key
            {0ul, "Not needed.", false},        // final key
            "OpenSSL SHA1.",                    // description
            OPENSSL_VERSION_TEXT                // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLSHA1Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLSHA1>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


OpenSSLSHA1::OpenSSLSHA1() {
    SHA1_Init(&sha_ctx_);
}


int OpenSSLSHA1::Add_(char const * data, std::uint64_t size) {
    return SHA1_Update(&sha_ctx_, data, size) == 1 ? 0 : 1;
}


int OpenSSLSHA1::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(20ul);
    return SHA1_Final(reinterpret_cast<unsigned char *>(result.data()), &sha_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLSHA1::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLSHA1::Initialize_(char const *, std::uint64_t) {
    return SHA1_Init(&sha_ctx_) == 1 ? 0 : 1;
}


void OpenSSLSHA1::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLSHA1Producer>());
}
