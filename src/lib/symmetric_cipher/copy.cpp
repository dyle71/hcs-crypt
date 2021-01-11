/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
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
            {0ul, "Not needed.", false},                                      // initial key
            {0ul, "Not needed.", false},                                      // final key
            "COPY: not a real cypher. Simply copies input to output.",        // description
            std::string{"hcs-crypt v"} + VERSION                              // provider
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


int Copy::Add_(char const * data, std::uint64_t size) {
    auto old_size = data_.size();
    data_.resize(old_size + size);
    auto p = reinterpret_cast<char *>(data_.data());
    std::memcpy(p + old_size, data, size);
    return 0;
}


int Copy::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.resize(data_.size());
    auto out = reinterpret_cast<char *>(result.data());
    auto in = reinterpret_cast<char const *>(data_.data());
    std::memcpy(out, in, result.size());
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