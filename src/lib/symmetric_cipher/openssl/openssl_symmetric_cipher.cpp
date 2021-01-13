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
