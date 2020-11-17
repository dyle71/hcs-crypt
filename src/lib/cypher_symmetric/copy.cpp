/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <headcode/crypt/factory.hpp>

#include "copy.hpp"


using namespace headcode::crypt;


/**
 * @brief   Produces instances of the algorithm.
 */
class CopyProducer : public Factory::Producer {
public:
    /**
     * @brief   Call operator - creates the algorithm.
     * @return  A new algorithm instance.
     */
    std::shared_ptr<Algorithm> operator()() const override {
        return std::make_shared<Copy>();
    }
};


int Copy::Initialize_() {
    return 0;
}


void Copy::Register() {
    Factory::Register("copy", Family::CYPHER_SYMMETRIC, std::make_shared<CopyProducer>());
}
