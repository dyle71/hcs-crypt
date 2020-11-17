/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_COPY_HPP
#define HEADCODE_SPACE_CRYPT_CYPHER_SYMMTERIC_COPY_HPP

#include <headcode/crypt/algorithm.hpp>
#include <headcode/crypt/factory.hpp>


namespace headcode::crypt {


class Copy : public Algorithm {

public:
    /**
     * @brief   Constructor.
     */
    Copy() : Algorithm{"copy", Family::CYPHER_SYMMETRIC} {
    }

    /**
     * @brief   Register this class of algorithms.
     */
    static void Register();

private:
    /**
     * @brief   Initialize this object instance.
     * This always returns 0.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize_() override;
};


}


#endif
