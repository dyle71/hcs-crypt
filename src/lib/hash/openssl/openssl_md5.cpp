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
            "openssl-md5",         // name
            Family::kHash,         // family
            "OpenSSL MD5.",        // description (short/left and long/below)

            "This is the MD5 message digest algorithm by Ronald Rivest. Originally intended to be a secure "
            "hash algorithm its weakness has been demonstrated and thus should not be used as a secure hash "
            "algorithm any longer. See: https://en.wikipedia.org/wiki/MD5.",

            OPENSSL_VERSION_TEXT,                     // provider
            64ul,                                     // input block size
            ProcessingBlockSize::kEmpty,              // output block size behaviour
            0ul,                                      // output block size (if changing)
            PaddingStrategy::PADDING_PKCS_5_7,        // default padding strategy
            16ul,                                     // result size
            {},                                       // initial data
            {}                                        // finalization data
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


int OpenSSLMD5::Add_(unsigned char const * block_incoming,
                     std::uint64_t size_incoming,
                     unsigned char *,
                     std::uint64_t & size_outgoing) {
    size_outgoing = GetDescription().block_size_outgoing_;
    return MD5_Update(&md5_ctx_, block_incoming, size_incoming) == 1 ? 0 : 1;
}


int OpenSSLMD5::Finalize_(unsigned char * result,
                          std::uint64_t,
                          std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return MD5_Final(result, &md5_ctx_) == 1 ? 0 : 1;
}


Algorithm::Description const & OpenSSLMD5::GetDescription_() const {
    return ::GetDescription();
}


int OpenSSLMD5::Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {
    return MD5_Init(&md5_ctx_) == 1 ? 0 : 1;
}


void OpenSSLMD5::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<OpenSSLMD5Producer>());
}
