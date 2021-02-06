# ------------------------------------------------------------
# This file is part of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020-2021 headcode.space e.U.  
# Oliver Maurhart <info@headcode.space>, https://www.headcode.space
# ------------------------------------------------------------

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CRYPT_SRC

    algorithm.cpp
    error.cpp
    factory.cpp
    family.cpp
    padding.cpp
    register.cpp

    symmetric_cipher/copy.cpp
    symmetric_cipher/ltc/aes/cbc/ltc_aes_128_cbc_decrypter.cpp
    symmetric_cipher/ltc/aes/cbc/ltc_aes_128_cbc_encrypter.cpp
    symmetric_cipher/ltc/aes/cbc/ltc_aes_192_cbc_decrypter.cpp
    symmetric_cipher/ltc/aes/cbc/ltc_aes_192_cbc_encrypter.cpp
    symmetric_cipher/ltc/aes/cbc/ltc_aes_256_cbc_decrypter.cpp
    symmetric_cipher/ltc/aes/cbc/ltc_aes_256_cbc_encrypter.cpp
    symmetric_cipher/ltc/aes/ecb/ltc_aes_128_ecb_decrypter.cpp
    symmetric_cipher/ltc/aes/ecb/ltc_aes_128_ecb_encrypter.cpp
    symmetric_cipher/ltc/aes/ecb/ltc_aes_192_ecb_decrypter.cpp
    symmetric_cipher/ltc/aes/ecb/ltc_aes_192_ecb_encrypter.cpp
    symmetric_cipher/ltc/aes/ecb/ltc_aes_256_ecb_decrypter.cpp
    symmetric_cipher/ltc/aes/ecb/ltc_aes_256_ecb_encrypter.cpp
    symmetric_cipher/ltc/ltc_symmetric_cipher.cpp

    hash/nohash.cpp
    hash/ltc/ltc_md5.cpp
    hash/ltc/ltc_ripemd128.cpp
    hash/ltc/ltc_ripemd160.cpp
    hash/ltc/ltc_ripemd256.cpp
    hash/ltc/ltc_ripemd320.cpp
    hash/ltc/ltc_sha1.cpp
    hash/ltc/ltc_sha224.cpp
    hash/ltc/ltc_sha256.cpp
    hash/ltc/ltc_sha384.cpp
    hash/ltc/ltc_sha512.cpp
    hash/ltc/ltc_tiger192.cpp
)

if (WITH_OPENSSL)
    set(OPENSSL_SRC

        hash/openssl/openssl_md5.cpp
        hash/openssl/openssl_ripemd160.cpp
        hash/openssl/openssl_sha1.cpp
        hash/openssl/openssl_sha224.cpp
        hash/openssl/openssl_sha256.cpp
        hash/openssl/openssl_sha384.cpp
        hash/openssl/openssl_sha512.cpp

        symmetric_cipher/openssl/aes/cbc/openssl_aes_128_cbc_decryptor.cpp
        symmetric_cipher/openssl/aes/cbc/openssl_aes_128_cbc_encryptor.cpp
        symmetric_cipher/openssl/aes/ecb/openssl_aes_128_ecb_decryptor.cpp
        symmetric_cipher/openssl/aes/ecb/openssl_aes_128_ecb_encryptor.cpp
        symmetric_cipher/openssl/aes/cbc/openssl_aes_192_cbc_decryptor.cpp
        symmetric_cipher/openssl/aes/cbc/openssl_aes_192_cbc_encryptor.cpp
        symmetric_cipher/openssl/aes/ecb/openssl_aes_192_ecb_decryptor.cpp
        symmetric_cipher/openssl/aes/ecb/openssl_aes_192_ecb_encryptor.cpp
        symmetric_cipher/openssl/aes/cbc/openssl_aes_256_cbc_decryptor.cpp
        symmetric_cipher/openssl/aes/cbc/openssl_aes_256_cbc_encryptor.cpp
        symmetric_cipher/openssl/aes/ecb/openssl_aes_256_ecb_decryptor.cpp
        symmetric_cipher/openssl/aes/ecb/openssl_aes_256_ecb_encryptor.cpp
        symmetric_cipher/openssl/openssl_symmetric_cipher.cpp
    )
endif ()


add_library(hcs-crypt STATIC ${CRYPT_SRC} ${OPENSSL_SRC})
target_link_libraries(hcs-crypt ${CMAKE_REQUIRED_LIBRARIES})
set_target_properties(hcs-crypt PROPERTIES VERSION ${VERSION})

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/headcode/crypt DESTINATION include COMPONENT header)
install(TARGETS hcs-crypt ARCHIVE DESTINATION lib COMPONENT library)
