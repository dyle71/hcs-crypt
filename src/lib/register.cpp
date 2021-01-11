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
#include "hash/ltc/ltc_sha1.hpp"
#include "hash/ltc/ltc_sha224.hpp"
#include "hash/ltc/ltc_sha256.hpp"
#include "hash/ltc/ltc_sha384.hpp"
#include "hash/ltc/ltc_sha512.hpp"
#include "hash/ltc/ltc_tiger192.hpp"

#ifdef OPENSSL
#include "hash/openssl/openssl_md5.hpp"
#include "hash/openssl/openssl_sha1.hpp"
#include "hash/openssl/openssl_sha224.hpp"
#include "hash/openssl/openssl_sha256.hpp"
#include "hash/openssl/openssl_sha384.hpp"
#include "hash/openssl/openssl_sha512.hpp"
#endif

void headcode::crypt::RegisterKnownAlgorithms() {

    Copy::Register();

    NoHash::Register();

    LTCMD5::Register();
    LTCSHA1::Register();
    LTCSHA224::Register();
    LTCSHA256::Register();
    LTCSHA384::Register();
    LTCSHA512::Register();
    LTCTIGER192::Register();

#ifdef OPENSSL
    OpenSSLMD5::Register();
    OpenSSLSHA1::Register();
    OpenSSLSHA224::Register();
    OpenSSLSHA256::Register();
    OpenSSLSHA384::Register();
    OpenSSLSHA512::Register();
#endif
}
