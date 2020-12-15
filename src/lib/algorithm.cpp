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


int Algorithm::Add(std::string const & text) {
    return Add(text.c_str(), text.size());
}


int Algorithm::Add(std::vector<std::byte> const & data) {
    return Add(reinterpret_cast<char const *>(data.data()), data.size());
}


int Algorithm::Add(char const * data, std::uint64_t size) {
    if (size > 0) {
        assert(data != nullptr && "Adding to algorithm with data is NULL/nullptr while data size is > 0.");
    }
    return Add_(data, size);
}


int Algorithm::Finalize(std::vector<std::byte> & result, std::vector<std::byte> const & data) {
    return Finalize(result, reinterpret_cast<char const *>(data.data()), data.size());
}


int Algorithm::Finalize(std::vector<std::byte> & result, char const * data, std::uint64_t size) {

    if (size > 0) {
        assert(data != nullptr && "Finalizing algorithm with data is NULL/nullptr while data size is > 0.");
    }

    int res = Finalize_(result, data, size);
    if (res == 0) {
        finalized_ = true;
    }

    return res;
}


Algorithm::Description const & Algorithm::GetDescription() const {
    return GetDescription_();
}


int Algorithm::Initialize(std::vector<std::byte> const & data) {
    return Initialize(reinterpret_cast<char const *>(data.data()), data.size());
}


int Algorithm::Initialize(char const * data, std::uint64_t size) {

    if (size > 0) {
        assert(data != nullptr && "Initializing algorithm with data is NULL/nullptr while data size is > 0.");
    }

    int res = 0;

    if (!IsInitialized()) {
        res = Initialize_(data, size);
        if (res == 0) {
            initialized_ = true;
        }
    }

    return res;
}
