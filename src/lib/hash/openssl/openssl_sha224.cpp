/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <headcode/crypt/factory.hpp>

#include <openssl/crypto.h>

#include "openssl_sha224.hpp"


using namespace headcode::crypt;


/**
 * @brief   The OpenSSL SHA224 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-sha224",                   // name
            Family::HASH,                       // family
            {0ul, "Not needed.", false},        // initial key
            {0ul, "Not needed.", false},        // final key
            "OpenSSL SHA224.",                  // description
            OPENSSL_VERSION_TEXT                // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLSHA224Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLSHA224>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


OpenSSLSHA224::OpenSSLSHA224() {
    SHA224_Init(&sha_ctx_);
}


int OpenSSLSHA224::Add_(char const * data, std::uint64_t size) {
    return SHA224_Update(&sha_ctx_, data, size) == 1 ? 0 : 1;
}


int OpenSSLSHA224::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(28ul);
    return SHA224_Final(reinterpret_cast<unsigned char *>(result.data()), &sha_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLSHA224::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLSHA224::Initialize_(char const *, std::uint64_t) {
    return SHA224_Init(&sha_ctx_) == 1 ? 0 : 1;
}


void OpenSSLSHA224::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLSHA224Producer>());
}
