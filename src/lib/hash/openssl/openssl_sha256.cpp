/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include <openssl/crypto.h>

#include "openssl_sha256.hpp"


using namespace headcode::crypt;


/**
 * @brief   The OpenSSL SHA256 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-sha256",                   // name
            Family::HASH,                       // family
            64ul,                               // input block size
            0ul,                                         // output block size
            32ul,                               // result size
            {0ul, "Not needed.", false},        // initial key
            {0ul, "Not needed.", false},        // final key
            "OpenSSL SHA256.",                  // description
            OPENSSL_VERSION_TEXT                // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLSHA256Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLSHA256>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


OpenSSLSHA256::OpenSSLSHA256() {
    SHA256_Init(&sha_ctx_);
}


int OpenSSLSHA256::Add_(char const * block_incoming, std::uint64_t size_incoming) {
    return SHA256_Update(&sha_ctx_, block_incoming, size_incoming) == 1 ? 0 : 1;
}


int OpenSSLSHA256::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(32ul);
    return SHA256_Final(reinterpret_cast<unsigned char *>(result.data()), &sha_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLSHA256::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLSHA256::Initialize_(char const *, std::uint64_t) {
    return SHA256_Init(&sha_ctx_) == 1 ? 0 : 1;
}


void OpenSSLSHA256::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLSHA256Producer>());
}
