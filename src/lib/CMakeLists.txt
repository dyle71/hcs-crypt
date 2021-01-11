# ------------------------------------------------------------
# This file is part of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020 headcode.space
# https://www.headcode.space, <info@headcode.space>
# ------------------------------------------------------------


set(CRYPT_SRC

    algorithm.cpp
    factory.cpp
    family.cpp
    register.cpp

    cypher_symmetric/copy.cpp

    hash/nohash.cpp
    hash/ltc/ltc_md5.cpp
    hash/ltc/ltc_sha1.cpp
    hash/ltc/ltc_sha224.cpp
    hash/ltc/ltc_sha256.cpp
    hash/ltc/ltc_sha384.cpp
    hash/ltc/ltc_sha512.cpp
)

if (WITH_OPENSSL)
    set(OPENSSL_SRC
        hash/openssl/openssl_md5.cpp
        hash/openssl/openssl_sha1.cpp
        hash/openssl/openssl_sha224.cpp
        hash/openssl/openssl_sha256.cpp
        hash/openssl/openssl_sha384.cpp
        hash/openssl/openssl_sha512.cpp
    )
endif ()


add_library(hcs-crypt STATIC ${CRYPT_SRC} ${OPENSSL_SRC})
target_link_libraries(hcs-crypt ${CMAKE_REQUIRED_LIBRARIES})
set_target_properties(hcs-crypt PROPERTIES VERSION ${VERSION})

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/headcode/crypt DESTINATION include COMPONENT header)
install(TARGETS hcs-crypt ARCHIVE DESTINATION lib COMPONENT library)
