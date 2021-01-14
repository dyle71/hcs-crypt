/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_HASH_OPENSSL_SHA512_HPP
#define HEADCODE_SPACE_CRYPT_HASH_OPENSSL_SHA512_HPP

#include <headcode/crypt/algorithm.hpp>

#include <openssl/sha.h>

namespace headcode::crypt {


/**
 * @brief   The OpenSSL SHA512 hash.
 */
class OpenSSLSHA512 : public Algorithm {

    SHA512_CTX sha_ctx_;        //!< @brief The OpenSSL SHA context used.

public:
    /**
     * @brief   Constructor.
     */
    OpenSSLSHA512();

    /**
     * @brief   Register this class of algorithms.
     */
    static void Register();

private:
    /**
     * @brief   Adds data to the algorithm
     * @param   block_incoming      incoming data block to add.
     * @param   size_incoming       size of the incoming data to add.
     * @param   block_outgoing      outgoing data block.
     * @param   size_outgoing       size of the outgoing data block (will be adjusted).
     * @return  0 if add was ok, else an error.
     */
    int Add_(unsigned char const * block_incoming,
             std::uint64_t size_incoming,
             unsigned char * block_outgoing,
             std::uint64_t & size_outgoing) override;

    /**
     * @brief   Finalizes this object instance.
     * @param   result                  the result of the algorithm.
     * @param   result_size             size of the result for finalization.
     * @param   finalization_data       the final data (== final key) to use, if any.
     * @return  0 if finalize was ok, else an error in the context of the concrete algorithm implementation.
     */
    int Finalize_(
            unsigned char * result,
            std::uint64_t result_size,
            std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & finalization_data) override;

    /**
     * @brief   Gets the algorithm description.
     * @return  A string describing the algorithm.
     * */
    Description const & GetDescription_() const override;

    /**
     * @brief   Initialize this object instance.
     * @param   initialization_data     the initial data (== initial key, IV, ...) to use, if any.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize_(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data)
            override;
};


}


#endif
