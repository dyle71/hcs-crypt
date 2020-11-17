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
    register.cpp

    cypher_symmetric/copy.cpp

    hash/nohash.cpp
)

add_library(hcs-crypt STATIC ${CRYPT_SRC})
target_link_libraries(hcs-crypt ${CMAKE_REQUIRED_LIBRARIES})
set_target_properties(hcs-crypt PROPERTIES VERSION ${VERSION})

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/headcode/crypt DESTINATION include COMPONENT header)
install(TARGETS hcs-crypt LIBRARY DESTINATION lib COMPONENT library)
