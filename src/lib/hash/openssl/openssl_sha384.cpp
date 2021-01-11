/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <headcode/crypt/factory.hpp>

#include <openssl/crypto.h>

#include "openssl_sha384.hpp"


using namespace headcode::crypt;


/**
 * @brief   The OpenSSL SHA384 algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "openssl-sha384",                   // name
            Family::HASH,                       // family
            {0ul, "Not needed.", false},        // initial key
            {0ul, "Not needed.", false},        // final key
            "OpenSSL SHA384.",                  // description
            OPENSSL_VERSION_TEXT                // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class OpenSSLSHA384Producer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<OpenSSLSHA384>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


OpenSSLSHA384::OpenSSLSHA384() {
    SHA384_Init(&sha_ctx_);
}


int OpenSSLSHA384::Add_(char const * data, std::uint64_t size) {
    return SHA384_Update(&sha_ctx_, data, size) == 1 ? 0 : 1;
}


int OpenSSLSHA384::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(48ul);
    return SHA384_Final(reinterpret_cast<unsigned char *>(result.data()), &sha_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLSHA384::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLSHA384::Initialize_(char const *, std::uint64_t) {
    return SHA384_Init(&sha_ctx_) == 1 ? 0 : 1;
}


void OpenSSLSHA384::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLSHA384Producer>());
}
