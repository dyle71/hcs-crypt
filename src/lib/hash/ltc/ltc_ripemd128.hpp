/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_LTC_RIPEMD128_HPP
#define HEADCODE_SPACE_CRYPT_HASH_LTC_RIPEMD128_HPP

#include <memory>

#include "ltc_hash.hpp"


namespace headcode::crypt {


/**
 * @brief   The libtomcrypt RIPEMD128 algorithm.
 */
class LTCRIPEMD128 : public LTCHash {

public:
    /**
     * @brief   Register this class of algorithms.
     */
    static void Register();

    /**
     * @brief   Constructor.
     */
    LTCRIPEMD128();

private:
    /**
     * @brief   Adds data to the algorithm
     * @param   block_incoming      the incoming data to add.
     * @param   size_incoming       size of the incoming data to add.
     * @return  0 if add was ok, else an error.
     */
    int Add_(char const * block_incoming, std::uint64_t size_incoming) override;

    /**
     * @brief   Finalizes this object instance.
     * @param   result      the result of the algorithm.
     * @param   data        the finalization data (== final key) to use, if any
     * @param   size        size of the data used for finalization.
     * @return  0 if finalize was ok, else an error.
     */
    int Finalize_(std::vector<std::byte> & result, char const * data, std::uint64_t size) override;

    /**
     * @brief   Gets the algorithm description.
     * @return  A string describing the algorithm.
     * */
    Description const & GetDescription_() const override;

    /**
     * @brief   Initialize this object instance.
     * This always returns 0.
     * @param   data        the initial data (== initial key) to use, if any
     * @param   size        size of the data used for initialization.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize_(char const * data, std::uint64_t size) override;
};


}


#endif
