/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>
#include <cstring>

#include <headcode/crypt/algorithm.hpp>


using namespace headcode::crypt;


int Algorithm::Add(const std::string & text) {
    std::vector<std::byte> ignored_outgoing;
    return Add(text, ignored_outgoing);
}


int Algorithm::Add(std::string const & text, std::vector<std::byte> & block_outgoing) {

    auto block_size_outgoing = GetDescription().block_size_outgoing_;
    if (block_size_outgoing == 0) {
        block_size_outgoing = text.size();
    }
    block_outgoing.resize(block_size_outgoing);

    return Add(text.c_str(), text.size(), reinterpret_cast<char *>(block_outgoing.data()), block_size_outgoing);
}


int Algorithm::Add(std::vector<std::byte> const & block_incoming) {
    std::vector<std::byte> ignored_outgoing;
    return Add(block_incoming, ignored_outgoing);
}


int Algorithm::Add(std::vector<std::byte> const & block_incoming, std::vector<std::byte> & block_outgoing) {

    auto block_size_outgoing = block_outgoing.size();
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


std::vector<std::byte> Algorithm::GrowToBlockSize(std::string const & text, std::uint64_t block_size) {
    std::uint64_t multiple = text.size() / block_size + (text.size() % block_size > 0 ? 1 : 0);
    std::vector<std::byte> res{multiple * block_size};
    std::memcpy(res.data(), text.data(), text.size());
    std::memset(res.data() + text.size(), 0, res.size() - text.size());
    return res;
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
