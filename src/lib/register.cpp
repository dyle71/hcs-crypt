/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include "register.hpp"

#include "hash/nohash.hpp"
#include "hash/ltc/ltc_md5.hpp"
#include "hash/ltc/ltc_ripemd128.hpp"
#include "hash/ltc/ltc_ripemd160.hpp"
#include "hash/ltc/ltc_ripemd256.hpp"
#include "hash/ltc/ltc_ripemd320.hpp"
#include "hash/ltc/ltc_sha1.hpp"
#include "hash/ltc/ltc_sha224.hpp"
#include "hash/ltc/ltc_sha256.hpp"
#include "hash/ltc/ltc_sha384.hpp"
#include "hash/ltc/ltc_sha512.hpp"
#include "hash/ltc/ltc_tiger192.hpp"

#ifdef OPENSSL
#include "hash/openssl/openssl_md5.hpp"
#include "hash/openssl/openssl_ripemd160.hpp"
#include "hash/openssl/openssl_sha1.hpp"
#include "hash/openssl/openssl_sha224.hpp"
#include "hash/openssl/openssl_sha256.hpp"
#include "hash/openssl/openssl_sha384.hpp"
#include "hash/openssl/openssl_sha512.hpp"
#endif

#include "symmetric_cipher/copy.hpp"
#include "symmetric_cipher/ltc/ltc_aes_128_ecb_decrypter.hpp"
#include "symmetric_cipher/ltc/ltc_aes_128_ecb_encrypter.hpp"

#ifdef OPENSSL
#include "symmetric_cipher/openssl/aes/cbc/openssl_aes_128_cbc_decryptor.hpp"
#include "symmetric_cipher/openssl/aes/cbc/openssl_aes_128_cbc_encryptor.hpp"
#include "symmetric_cipher/openssl/aes/ecb/openssl_aes_128_ecb_decryptor.hpp"
#include "symmetric_cipher/openssl/aes/ecb/openssl_aes_128_ecb_encryptor.hpp"
#include "symmetric_cipher/openssl/aes/cbc/openssl_aes_192_cbc_decryptor.hpp"
#include "symmetric_cipher/openssl/aes/cbc/openssl_aes_192_cbc_encryptor.hpp"
#include "symmetric_cipher/openssl/aes/ecb/openssl_aes_192_ecb_decryptor.hpp"
#include "symmetric_cipher/openssl/aes/ecb/openssl_aes_192_ecb_encryptor.hpp"
#include "symmetric_cipher/openssl/aes/cbc/openssl_aes_256_cbc_decryptor.hpp"
#include "symmetric_cipher/openssl/aes/cbc/openssl_aes_256_cbc_encryptor.hpp"
#include "symmetric_cipher/openssl/aes/ecb/openssl_aes_256_ecb_decryptor.hpp"
#include "symmetric_cipher/openssl/aes/ecb/openssl_aes_256_ecb_encryptor.hpp"
#endif


void headcode::crypt::RegisterKnownAlgorithms() {

    NoHash::Register();

    LTCMD5::Register();
    LTCRIPEMD128::Register();
    LTCRIPEMD160::Register();
    LTCRIPEMD256::Register();
    LTCRIPEMD320::Register();
    LTCSHA1::Register();
    LTCSHA224::Register();
    LTCSHA256::Register();
    LTCSHA384::Register();
    LTCSHA512::Register();
    LTCTIGER192::Register();

    Copy::Register();

    LTCAES128ECBDecrypter::Register();
    LTCAES128ECBEncrypter::Register();

#ifdef OPENSSL

    OpenSSLMD5::Register();
    OpenSSLRIPEMD160::Register();
    OpenSSLSHA1::Register();
    OpenSSLSHA224::Register();
    OpenSSLSHA256::Register();
    OpenSSLSHA384::Register();
    OpenSSLSHA512::Register();

    OpenSSLAES128CBCDecrypter::Register();
    OpenSSLAES128CBCEncrypter::Register();
    OpenSSLAES128ECBDecrypter::Register();
    OpenSSLAES128ECBEncrypter::Register();
    OpenSSLAES192CBCDecrypter::Register();
    OpenSSLAES192CBCEncrypter::Register();
    OpenSSLAES192ECBDecrypter::Register();
    OpenSSLAES192ECBEncrypter::Register();
    OpenSSLAES256CBCDecrypter::Register();
    OpenSSLAES256CBCEncrypter::Register();
    OpenSSLAES256ECBDecrypter::Register();
    OpenSSLAES256ECBEncrypter::Register();

#endif
}
