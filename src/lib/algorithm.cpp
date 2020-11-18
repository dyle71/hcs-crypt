/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <cassert>
#include <headcode/crypt/algorithm.hpp>


using namespace headcode::crypt;


int Algorithm::Add(std::vector<std::byte> const & data) {
    return Add(reinterpret_cast<char const *>(data.data()), data.size());
}


int Algorithm::Add(char const * data, std::uint64_t size) {
    if (size > 0) {
        assert(data != nullptr);
    }
    return Add_(data, size);
}


std::string Algorithm::GetDescription() const {
    return GetDescription_();
}


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
