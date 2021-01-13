/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_LTC_MD5_HPP
#define HEADCODE_SPACE_CRYPT_HASH_LTC_MD5_HPP

#include <memory>

#include "ltc_hash.hpp"


namespace headcode::crypt {


/**
 * @brief   The libtomcrypt MD5 algorithm.
 */
class LTCMD5 : public LTCHash {

public:
    /**
     * @brief   Register this class of algorithms.
     */
    static void Register();

    /**
     * @brief   Constructor.
     */
    LTCMD5();

private:
    /**
     * @brief   Adds data to the algorithm
     * @param   block_incoming      the incoming data to add.
     * @param   size_incoming       size of the incoming data to add.
     * @param   block_outgoing      outgoing data block.
     * @param   size_outgoing       size of the outgoing data block (will be adjusted).
     * @return  0 if add was ok, else an error.
     */
    int Add_(char const * block_incoming,
             std::uint64_t size_incoming,
             char * block_outgoing,
             std::uint64_t & size_outgoing) override;

    /**
     * @brief   Finalizes this object instance.
     * @param   result          the result of the algorithm.
     * @param   rtesult_size    size of the result for finalization.
     * @param   data            the finalization data (== final key) to use, if any
     * @param   data_size       size of the data used for finalization.
     * @return  0 if finalize was ok, else an error in the context of the concrete algorithm implementation.
     */
    int Finalize_(char * result, std::uint64_t result_size, char const * data, std::uint64_t data_size) override;

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
