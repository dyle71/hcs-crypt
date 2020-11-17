/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Nohashright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <headcode/crypt/factory.hpp>

#include "nohash.hpp"


using namespace headcode::crypt;


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
};


int NoHash::Initialize_() {
    return 0;
}


void NoHash::Register() {
    Factory::Register("nohash", Family::HASH, std::make_shared<NoHashProducer>());
}
