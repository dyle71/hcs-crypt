/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cstring>

#include <headcode/crypt/factory.hpp>

#include "copy.hpp"

using namespace headcode::crypt;


/**
 * @brief   The COPY algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {

    static Algorithm::Description description = {
            "copy",                                                           // name
            Family::SYMMETRIC_CIPHER,                                         // family
            0ul,                                                              // input block size
            0ul,                                                              // output block size
            0ul,                                                              // result size
            {0ul, "No initial data needed.", false},                          // initial data
            {0ul, "No finalization data needed.", false},                     // finalization data
            "COPY: not a real cypher. Simply copies input to output.",        // description (short/left and long/below)

            "This a No-Operation dummy pseudo-cipher algorithm.",

            std::string{"hcs-crypt v"} + VERSION        // provider
    };

    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class CopyProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::unique_ptr<Algorithm> operator()() const override {
        return std::make_unique<Copy>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int Copy::Add_(char const * block_incoming,
               std::uint64_t size_incoming,
               char * block_outgoing,
               std::uint64_t & size_outgoing) {

    if (size_outgoing < GetDescription().block_size_outgoing_) {
        // We need at least block_size_outgoing space in the target
        return 1;
    }

    auto copy_size = std::min(size_incoming, size_outgoing);
    std::memcpy(block_outgoing, block_incoming, copy_size);
    if (copy_size < size_outgoing) {
        std::memset(block_outgoing + copy_size, 0, size_outgoing - copy_size);
    }

    return 0;
}


int Copy::Finalize_(char * result, std::uint64_t, char const * , std::uint64_t) {
    if (result != nullptr) {
        *result = 0;
    }
    return 0;
}


Algorithm::Description const & Copy::GetDescription_() const {
    return ::GetDescription();
}


int Copy::Initialize_(char const *, std::uint64_t) {
    return 0;
}


void Copy::Register() {
    auto const & description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<CopyProducer>());
}
