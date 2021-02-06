/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>

#include <headcode/logger/logger.hpp>
#include <headcode/crypt/error.hpp>

#include "openssl_symmetric_cipher.hpp"

using namespace headcode::crypt;


OpenSSLSymmetricCipher::OpenSSLSymmetricCipher(bool encrypt) : ctx_{EVP_CIPHER_CTX_new()}, encrypt_{encrypt} {
    EVP_CIPHER_CTX_init(ctx_);
}


OpenSSLSymmetricCipher::~OpenSSLSymmetricCipher() noexcept {
    EVP_CIPHER_CTX_free(ctx_);
}


int OpenSSLSymmetricCipher::Add_(unsigned char const * block_incoming,
                                 std::uint64_t size_incoming,
                                 unsigned char * block_outgoing,
                                 std::uint64_t & size_outgoing) {

    int out_size = size_outgoing;
    auto res = EVP_CipherUpdate(GetCipherContext(), block_outgoing, &out_size, block_incoming, size_incoming);
    size_outgoing = out_size;
    if (res != 1) {
        return 1;
    }

    return static_cast<int>(Error::kNoError);
}


int OpenSSLSymmetricCipher::Finalize_(unsigned char *,
                                      std::uint64_t,
                                      std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const &) {

    return static_cast<int>(Error::kNoError);
}


int OpenSSLSymmetricCipher::Initialize_(
        const std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> & initialization_data) {

    int res = EVP_CipherInit_ex(GetCipherContext(), GetCipher(), nullptr, nullptr, nullptr, IsEncryptor() ? 1 : 0);
    if (res != 1) {
        return 1;
    }

    unsigned char const * key_data = nullptr;
    if (!VerifyInitValue(key_data, initialization_data, "key", EVP_CIPHER_CTX_key_length)) {
        return 1;
    }

    unsigned char const * iv_data = nullptr;
    if (!VerifyInitValue(iv_data, initialization_data, "iv", EVP_CIPHER_CTX_iv_length)) {
        return 1;
    }

    auto e = EVP_CipherInit_ex(GetCipherContext(), nullptr, nullptr, key_data, iv_data, IsEncryptor() ? 1 : 0);
    return e == 1 ? static_cast<int>(Error::kNoError) : 1;
}


bool OpenSSLSymmetricCipher::VerifyInitValue(
        unsigned char const *& data,
        const std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> & initialization_data,
        std::string const & name,
        int (*EVP_GET_LENGTH)(EVP_CIPHER_CTX const *)) const {

    data = nullptr;

    auto definition_iter = GetDescription().initialization_argument_.find(name);
    if (definition_iter == GetDescription().initialization_argument_.end()) {
        return true;
    }

    bool mandatory = !definition_iter->second.optional_;
    auto iter = initialization_data.find(name);
    if (iter == initialization_data.end() && mandatory) {
        return false;
    }

    if (iter != initialization_data.end()) {

        data = std::get<0>(iter->second);
        std::uint64_t size = std::get<1>(iter->second);
        if ((size > 0) && (data == nullptr)) {
            headcode::logger::Warning{"headcode.crypt"} << "Applying data which is NULL/nullptr while size is > 0.";
            return false;
        }
        if (static_cast<int>(size) != EVP_GET_LENGTH(GetCipherContext())) {
            return false;
        }
    }

    return true;
}
