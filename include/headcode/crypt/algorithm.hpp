/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_ALGORITHM_HPP
#define HEADCODE_SPACE_CRYPT_ALGORITHM_HPP

#include <cstddef>
#include <string>
#include <vector>
#include <utility>

#include "family.hpp"


namespace headcode::crypt {


/**
 * @brief   The Algorithm class is the abstract class for any crypto-algorithm.
 */
class Algorithm {

public:
    /**
     * @brief   This holds the algorithm description.
     */
    struct Description {
        /**
         * @brief   This structure defines requirements for keys used.
         * This structure describes the requirement for key data used in the algorithms.
         * Some algorithms need initial key values, some need final key values, some need none, some need both.
         * The `needed_` field defines if the particular key is needed at all and the `size_` field
         * holds the size in bytes of the key needed.
         * NOTE: a `size_` field value of 0 with `needed_` set to true, indicates that the size of the
         * key needed is not fixed.
         */
        struct KeyDefinition {
            bool needed_ = false;        //!< @brief States that this key is needed.
            std::uint64_t size_;         //!< @brief Defines the size in bytes of the key (special meaning for value 0).
        };
        std::string name_;                            //!< @brief The name of this algorithm.
        Family family_;                               //!< @brief The family of the algorithm.
        KeyDefinition initial_key_definition_;        //!< @brief The requirements of the initial key used.
        KeyDefinition final_key_definition_;          //!< @brief The requirements of the final key used.
        std::string description_;                     //!< @brief A human readable description of the algorithm.
    };

private:
    bool finalized_ = false;          //!< @brief Finalized flag.
    bool initialized_ = false;        //!< @brief Initialized flag.

public:
    /**
     * @brief   Constructor.
     */
    Algorithm() = default;

    /**
     * @brief   Copy Constructor.
     */
    Algorithm(Algorithm const &) = default;

    /**
     * @brief   Move Constructor.
     */
    Algorithm(Algorithm &&) = default;

    /**
     * @brief   Destructor.
     */
    virtual ~Algorithm() = default;

    /**
     * @brief   Assignment.
     * @return  this.
     */
    Algorithm & operator=(Algorithm const &) = default;

    /**
     * @brief   Move Assignment.
     * @return  this.
     */
    Algorithm & operator=(Algorithm &&) = default;

    /**
     * @brief   Adds text to the algorithm
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   text        the text to add.
     * @return  0 if initialize was ok, else an error.
     */
    int Add(std::string const & text);

    /**
     * @brief   Adds data to the algorithm
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   data        the data to add.
     * @return  0 if initialize was ok, else an error.
     */
    int Add(std::vector<std::byte> const & data);

    /**
     * @brief   Adds data to the algorithm
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   data        the data to add.
     * @param   size        size of the data to add.
     * @return  0 if initialize was ok, else an error.
     */
    int Add(char const * data, std::uint64_t size);

    /**
     * @brief   Finalizes this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * You may Finalize the object multiple times.
     * @param   result      the result of the algorithm.
     * @param   data        the final data (== final key) to use, if any
     * @return  0 if initialize was ok, else an error.
     */
    int Finalize(std::vector<std::byte> & result, std::vector<std::byte> const & data = {});

    /**
     * @brief   Finalizes this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * You may Finalize the object multiple times.
     * @param   result      the result of the algorithm.
     * @param   data        the finalization data (== final key) to use, if any
     * @param   size        size of the data used for finalization.
     * @return  0 if initialize was ok, else an error.
     */
    int Finalize(std::vector<std::byte> & result, char const * data, std::uint64_t size);

    /**
     * @brief   Gets the algorithm description.
     * @return  A string describing the algorithm.
     * */
    Description const & GetDescription() const;

    /**
     * @brief   Initialize this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * The object **WILL NOT** be initialzed twice.
     * @param   data        the initial data (== initial key) to use, if any
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize(std::vector<std::byte> const & data = {});

    /**
     * @brief   Initialize this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * The object **WILL NOT** be initialzed twice.
     * @param   data        the initial data (== initial key) to use, if any
     * @param   size        size of the data used for initialization.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize(char const * data, std::uint64_t size);

    /**
     * @brief   Checks if this algorithm instance has been finalized.
     * @return  true, if we finalized this algorithm object.
     */
    bool IsFinalized() const {
        return finalized_;
    }

    /**
     * @brief   Checks if this algorithm instance has been initialized.
     * @return  true, if we init this algorithm object.
     */
    bool IsInitialized() const {
        return initialized_;
    }

private:
    /**
     * @brief   Adds data to the algorithm
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   data        the data to add.
     * @param   size        size of the data to add.
     * @return  0 if initialize was ok, else an error.
     */
    virtual int Add_(char const * data, std::uint64_t size) = 0;

    /**
     * @brief   Finalizes this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   result      the result of the algorithm.
     * @param   data        the finalization data (== final key) to use, if any
     * @param   size        size of the data used for finalization.
     * @return  0 if initialize was ok, else an error.
     */
    virtual int Finalize_(std::vector<std::byte> & result, char const * data, std::uint64_t size) = 0;

    /**
     * @brief   Gets the algorithm description.
     * @return  A string describing the algorithm.
     * */
    virtual Description const & GetDescription_() const = 0;

    /**
     * @brief   Initialize this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   data        the initial data (== initial key) to use, if any
     * @param   size        size of the data used for initialization.
     * @return  0 if initialize was ok, else an error.
     */
    virtual int Initialize_(char const * data, std::uint64_t size) = 0;
};


}


#endif
