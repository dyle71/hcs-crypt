/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>

#include <headcode/crypt/algorithm.hpp>


using namespace headcode::crypt;


int Algorithm::Add(std::string const & text, std::vector<std::byte> & block_outgoing) {
    auto block_size_outgoing = GetDescription().block_size_outgoing_;
    block_outgoing.resize(block_size_outgoing);
    return Add(text.c_str(), text.size(), reinterpret_cast<char *>(block_outgoing.data()), block_size_outgoing);
}


int Algorithm::Add(std::vector<std::byte> const & block_incoming, std::vector<std::byte> & block_outgoing) {
    auto block_size_outgoing = GetDescription().block_size_outgoing_;
    block_outgoing.resize(block_size_outgoing);
    return Add(reinterpret_cast<char const *>(block_incoming.data()),
               block_incoming.size(),
               reinterpret_cast<char *>(block_outgoing.data()),
               block_size_outgoing);
}


int Algorithm::Add(char const * block_incoming,
                   std::uint64_t size_incoming,
                   char * block_outgoing,
                   std::uint64_t & size_outgoing) {

    if (size_incoming > 0) {
        assert(block_incoming != nullptr &&
               "Adding to algorithm with incoming block is NULL/nullptr while incoming size is > 0.");
    }
    if (size_outgoing > 0) {
        assert(block_outgoing != nullptr &&
               "Adding to algorithm with outgoing block is NULL/nullptr while outgoing size is > 0.");
    }

    return Add_(block_incoming, size_incoming, block_outgoing, size_outgoing);
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
