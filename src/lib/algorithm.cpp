/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <headcode/crypt/algorithm.hpp>


using namespace headcode::crypt;


int Algorithm::Initialize() {

    int res = 0;

    if (!IsInitialized()) {
        res = Initialize_();
        if (res == 0) {
            initialized_ = true;
        }
    }

    return res;
}
