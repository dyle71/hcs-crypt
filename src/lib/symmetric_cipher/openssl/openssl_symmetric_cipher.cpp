/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include "openssl_symmetric_cipher.hpp"

using namespace headcode::crypt;


OpenSSLSymmetricCipher::OpenSSLSymmetricCipher(bool encrypt) : ctx_{EVP_CIPHER_CTX_new()}, encrypt_{encrypt} {
    EVP_CIPHER_CTX_init(ctx_);
}


OpenSSLSymmetricCipher::~OpenSSLSymmetricCipher() noexcept {
    EVP_CIPHER_CTX_free(ctx_);
}


int OpenSSLSymmetricCipher::Add_(char const * block_incoming,
                                 std::uint64_t size_incoming,
                                 char * block_outgoing,
                                 std::uint64_t & size_outgoing) {

    // some rather wild (unnecessary) casting...
    auto out = reinterpret_cast<unsigned char *>(block_outgoing);
    int out_size = size_outgoing;
    auto in = reinterpret_cast<const unsigned char *>(block_incoming);

    auto res = EVP_CipherUpdate(GetCipherContext(), out, &out_size, in, size_incoming);
    size_outgoing = out_size;
    if (res != 1) {
        return 1;
    }

    return 0;
}


int OpenSSLSymmetricCipher::Finalize_(char *, std::uint64_t, char const *, std::uint64_t) {
    return 0;
}


int OpenSSLSymmetricCipher::Initialize_(char const * data, std::uint64_t size) {

    int res = EVP_CipherInit_ex(GetCipherContext(), GetCipher(), nullptr, nullptr, nullptr, IsEncryptor() ? 1 : 0);
    if (res != 1) {
        return 1;
    }

    // we assume that the key and iv are concatenated in the memory
    std::uint64_t inner_key_size = EVP_CIPHER_CTX_key_length(GetCipherContext());
    std::uint64_t inner_iv_size = EVP_CIPHER_CTX_iv_length(GetCipherContext());
    auto total_init_size = inner_key_size + inner_iv_size;
    if (total_init_size != GetDescription().initial_argument_.size_) {
        return 1;
    }
    if (total_init_size != size) {
        return 1;
    }

    auto d = reinterpret_cast<const unsigned char *>(data);
    res = EVP_CipherInit_ex(GetCipherContext(), nullptr, nullptr, d, d + inner_key_size, IsEncryptor() ? 1 : 0);

    if (res != 1) {
        return 1;
    }

    return 0;
}
