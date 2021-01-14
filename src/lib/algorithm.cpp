/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>
#include <cstring>

#include <headcode/mem/mem.hpp>
#include <headcode/crypt/algorithm.hpp>


using namespace headcode::crypt;


int Algorithm::Add(const std::string & text) {
    std::vector<std::byte> ignored_outgoing;
    return Add(text, ignored_outgoing);
}


int Algorithm::Add(std::string const & text, std::vector<std::byte> & block_outgoing) {
    auto block_incoming = headcode::mem::StringToMemory(text);
    return Add(block_incoming, block_outgoing);
}


int Algorithm::Add(std::vector<std::byte> const & block_incoming) {
    std::vector<std::byte> ignored_outgoing;
    return Add(block_incoming, ignored_outgoing);
}


int Algorithm::Add(std::vector<std::byte> const & block_incoming, std::vector<std::byte> & block_outgoing) {

    // In here we do the padding of the incoming (and outgoing) data.

    auto block_incoming_data = reinterpret_cast<unsigned char const *>(block_incoming.data());
    auto block_incoming_data_size = block_incoming.size();

    std::vector<std::byte> padded_block_incoming;
    auto const & description = GetDescription();
    if ((GetBlockPaddingStrategy() != PaddingStrategy::PADDING_NONE) && (description.block_size_incoming_ != 0)) {

        // This line below is expensive.
        padded_block_incoming = block_incoming;
        Pad(padded_block_incoming, description.block_size_incoming_, GetBlockPaddingStrategy());

        block_incoming_data = reinterpret_cast<unsigned char const *>(padded_block_incoming.data());
        block_incoming_data_size = padded_block_incoming.size();
    }

    if (description.block_size_outgoing_ != 0) {
        block_outgoing.resize(block_incoming_data_size);
        Pad(block_outgoing, description.block_size_outgoing_, GetBlockPaddingStrategy());
    }

    auto block_outgoing_data = reinterpret_cast<unsigned char *>(block_outgoing.data());
    auto block_outgoing_data_size = block_outgoing.size();

    return Add(block_incoming_data, block_incoming_data_size, block_outgoing_data, block_outgoing_data_size);
}


int Algorithm::Add(unsigned char const * block_incoming,
                   std::uint64_t size_incoming,
                   unsigned char * block_outgoing,
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


int Algorithm::Finalize(std::vector<std::byte> & result,
                        std::map<std::string, std::vector<std::byte>> const & finalization_data) {

    std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> fd;
    for (auto const & [name, memory] : finalization_data) {
        auto data = reinterpret_cast<unsigned char const *>(memory.data());
        auto size = memory.size();
        fd[name] = std::make_tuple(data, size);
    };

    return Finalize(result, fd);
}


int Algorithm::Finalize(
        std::vector<std::byte> & result,
        std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & finalization_data) {

    // In here we do the padding of the finalization data.

    // padded_data is the holder we pass on to the next level deep down
    // local_padded_data is a helper to keep temporary padded memory until we get out of scope here

    std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> padded_data;
    std::map<std::string, std::vector<std::byte>> local_padded_data;

    auto const & description = GetDescription();
    for (auto const & [name, memory] : finalization_data) {

        auto [data, size] = memory;
        auto iter = description.finalization_argument_.find(name);
        if (iter != description.finalization_argument_.end()) {

            auto const & argument_definition = (*iter).second;
            if ((argument_definition.size_ > 0) && (argument_definition.size_ != size) &&
                (argument_definition.padding_strategy_ != PaddingStrategy::PADDING_NONE)) {

                // the current argument needs a padding... =(

                local_padded_data.emplace(std::make_pair(name, std::vector<std::byte>{size}));
                std::memcpy(local_padded_data[name].data(), data, size);
                Pad(local_padded_data[name], argument_definition.size_, argument_definition.padding_strategy_);

                data = reinterpret_cast<unsigned char const *>(local_padded_data[name].data());
                size = local_padded_data[name].size();
            }
        }

        padded_data[name] = std::make_tuple(data, size);
    }

    return Finalize(reinterpret_cast<unsigned char *>(result.data()), result.size(), padded_data);
}


int Algorithm::Finalize(
        unsigned char * result,
        std::uint64_t result_size,
        std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & finalization_data) {

    if (result_size > 0) {
        assert(result != nullptr && "Finalizing algorithm with result is NULL/nullptr while result size is > 0.");
    }

    for (auto const & [name, memory] : finalization_data) {
        auto [data, size] = memory;
        if (size > 0) {
            assert(data != nullptr && "Finalizing algorithm with a data part is NULL/nullptr while data size is > 0.");
        }
    }

    int res = Finalize_(result, result_size, finalization_data);
    if (res == 0) {
        finalized_ = true;
    }

    return res;
}


Algorithm::Description const & Algorithm::GetDescription() const {
    return GetDescription_();
}


int Algorithm::Initialize(std::map<std::string, std::vector<std::byte>> const & initialization_data) {

    // In here we do the padding of the finalization data.

    // padded_data is the holder we pass on to the next level deep down
    // local_padded_data is a helper to keep temporary padded memory until we get out of scope here

    std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> padded_data;
    std::map<std::string, std::vector<std::byte>> local_padded_data;

    auto const & description = GetDescription();
    for (auto const & [name, memory] : initialization_data) {

        auto data = reinterpret_cast<unsigned char const *>(memory.data());
        auto size = memory.size();

        auto iter = description.initialization_argument_.find(name);
        if (iter != description.initialization_argument_.end()) {

            auto const & argument_definition = (*iter).second;
            if ((argument_definition.size_ > 0) && (argument_definition.size_ != size) &&
                (argument_definition.padding_strategy_ != PaddingStrategy::PADDING_NONE)) {

                // the current argument needs a padding... =(

                local_padded_data.emplace(std::make_pair(name, std::vector<std::byte>{memory.size()}));
                std::memcpy(local_padded_data[name].data(), data, size);
                Pad(local_padded_data[name], argument_definition.size_, argument_definition.padding_strategy_);

                data = reinterpret_cast<unsigned char const *>(local_padded_data[name].data());
                size = local_padded_data[name].size();
            }
        }

        padded_data[name] = std::make_tuple(data, size);
    }

    return Initialize(padded_data);
}


int Algorithm::Initialize(
        std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data) {

    for (auto const & [name, memory] : initialization_data) {
        auto [data, size] = memory;
        if (size > 0) {
            assert(data != nullptr &&
                   "Initializing algorithm with a data part is NULL/nullptr while data size is > 0.");
        }
    }

    int res = 0;
    if (!IsInitialized()) {
        res = Initialize_(initialization_data);
        if (res == 0) {
            finalized_ = true;
        }
    }

    return res;
}
