/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include "register.hpp"

#include "cypher_symmetric/copy.hpp"

#include "hash/nohash.hpp"
#include "hash/ltc/ltc_md5.hpp"

#ifdef OPENSSL
#include "hash/openssl/openssl_md5.hpp"
#endif

void headcode::crypt::RegisterKnownAlgorithms() {

    Copy::Register();

    NoHash::Register();
    LTCMD5::Register();

#ifdef OPENSSL
    OpenSSLMD5::Register();
#endif
}
