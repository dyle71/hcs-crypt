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


void headcode::crypt::RegisterKnownAlgorithms() {
    Copy::Register();
    NoHash::Register();
}
