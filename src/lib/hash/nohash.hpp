/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Nohashright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_NOHASH_HPP
#define HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_NOHASH_HPP

#include <headcode/crypt/algorithm.hpp>


namespace headcode::crypt {


class NoHash : public Algorithm {

public:
    /**
     * @brief   Constructor.
     */
    NoHash() : Algorithm{"nohash", Family::HASH} {
    }

    /**
     * @brief   Register this class of algorithms.
     */
    static void Register();

private:
    /**
     * @brief   Returns the description of the algorithm.
     * @return  A string describing the algorithm.
     */
    std::string GetDescription_() const override {
        return "This is not a real hash. It always returns 0 as hash 'value'.";
    }

    /**
     * @brief   Initialize this object instance.
     * This always returns 0.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize_() override;
};


}


#endif
