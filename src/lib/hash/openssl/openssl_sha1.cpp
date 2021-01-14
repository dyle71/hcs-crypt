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
            "openssl-sha1",         // name
            Family::HASH,           // family
            "OpenSSL SHA1.",        // description (short/left and long/below)

            "This is the Secure Hash Algorithm 1 as defined by the NSA. The NIST formaly deprecated the use of "
            "this algorithms due to discovered weaknesses. See: https://en.wikipedia.org/wiki/SHA-1.",

            OPENSSL_VERSION_TEXT,                     // provider
            64ul,                                     // input block size
            0ul,                                      // output block size
            PaddingStrategy::PADDING_PKCS_5_7,        // default padding strategy
            20ul,                                     // result size
            {},                                       // initial data
            {}                                        // finalization data

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


int OpenSSLSHA1::Add_(unsigned char const * block_incoming,
                      std::uint64_t size_incoming,
                      unsigned char *,
                      std::uint64_t & size_outgoing) {
    size_outgoing = GetDescription().block_size_outgoing_;
    return SHA1_Update(&sha_ctx_, block_incoming, size_incoming) == 1 ? 0 : 1;
}


int OpenSSLSHA1::Finalize_(unsigned char * result,
                           std::uint64_t,
                           std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return SHA1_Final(result, &sha_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLSHA1::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLSHA1::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return SHA1_Init(&sha_ctx_) == 1 ? 0 : 1;
}


void OpenSSLSHA1::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLSHA1Producer>());
}
