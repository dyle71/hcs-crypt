/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <headcode/crypt/factory.hpp>
#include <headcode/crypt/hash/nohash.hpp>

using namespace headcode::crypt;


/**
 * @brief   The NOHASH algorithm description.
 * @return  The description of this algorithm.
 */
static Algorithm::Description const & GetDescription() {
    static Algorithm::Description description = {
            "nohash",                                          // name
            Family::HASH,                                      // family
            {0ul, false},                                      // initial key
            {0ul, false},                                      // final key
            "NOHASH: not a real hash, always return 0."        // description
    };
    return description;
}


/**
 * @brief   Produces instances of the algorithm.
 */
class NoHashProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::shared_ptr<Algorithm> operator()() const override {
        return std::make_shared<NoHash>();
    }

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     */
    Algorithm::Description const & GetDescription() const override {
        return ::GetDescription();
    }
};


int NoHash::Add_(char const *, std::uint64_t) {
    return 0;
}


int NoHash::Finalize_(std::vector<std::byte> & result, char const *, std::uint64_t) {
    result.clear();
    return 0;
}


Algorithm::Description const & NoHash::GetDescription_() const {
    return ::GetDescription();
}


int NoHash::Initialize_(char const *, std::uint64_t) {
    return 0;
}


void NoHash::Register() {
    auto description = ::GetDescription();
    Factory::Register(description.name_, description.family_, std::make_shared<NoHashProducer>());
}
