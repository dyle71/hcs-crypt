/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_OPENSSL_RIPEMD160_HPP
#define HEADCODE_SPACE_CRYPT_HASH_OPENSSL_RIPEMD160_HPP

#include <headcode/crypt/algorithm.hpp>

#include <openssl/ripemd.h>

namespace headcode::crypt {


/**
 * @brief   The OpenSSL RIPEMD160 hash.
 */
class OpenSSLRIPEMD160 : public Algorithm {

    RIPEMD160_CTX ripemd160_ctx_;        //!< @brief The OpenSSL RIPEMD160 context used.

public:
    /**
     * @brief   Constructor.
     */
    OpenSSLRIPEMD160();

    /**
     * @brief   Register this class of algorithms.
     */
    static void Register();

private:
    /**
     * @brief   Adds data to the algorithm
     * @param   data        the data to add.
     * @param   size        size of the data to add.
     * @return  0 if add was ok, else an error.
     */
    int Add_(char const * data, std::uint64_t size) override;

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
