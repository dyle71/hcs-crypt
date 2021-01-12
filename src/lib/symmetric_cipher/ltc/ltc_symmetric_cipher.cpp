/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <headcode/crypt/factory.hpp>

#include "ltc_symmetric_cipher.hpp"

using namespace headcode::crypt;


LTCSymmetricCipher::~LTCSymmetricCipher() noexcept {
    if (descriptor_ != nullptr) {
        unregister_cipher(descriptor_);
        descriptor_ = nullptr;
    }
}


int LTCSymmetricCipher::SetDescriptor(ltc_cipher_descriptor const * descriptor) {

    if (descriptor_ != nullptr) {
        unregister_cipher(nullptr);
    }

    int res = 0;

    descriptor_ = descriptor;
    if (descriptor_ != nullptr) {
        res = register_cipher(descriptor_);
    }

    return res;
}
