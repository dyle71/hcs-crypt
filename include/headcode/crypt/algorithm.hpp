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
 * Hashes, encryptor and decrypter are all algorithms in this sense:
 * - an algorithm instance is created. This may or may not use an initial key.
 * - data is (repeatedly) added to the algorithm instance, which changes its inner state.
 * - at last the algorithm instance is finalized, again sometimes with a final key and sometime not.
 * If an initial and/or a final key is used depends on the algorithm itself and can be queried by
 * inspecting the Algorithm::Description.
 * This is a very broad definition and probably not only crypto algorithm fit this approach, since
 * the initial and final keys themselves are basically just memory BLOBs holding anything an
 * algorithm can interpret as initial (or final) data to process.
 * There is one single limitation: an algorithm may be initialized only once but finalized multiple times.
 */
class Algorithm {

public:
    /**
     * @brief   This holds the algorithm description.
     */
    struct Description {
        /**
         * @brief   This structure defines requirements for input data (most likely the key) used.
         * This structure describes the requirement for input data used in the algorithms. Some algorithms need
         * initial key values, some need final key values, some need none, some need both. The `needed_` field
         * defines if the particular key is needed at all and the `size_` field holds the size in bytes of the
         * key needed. **NOTE**: a `size_` field value of 0 with `needed_` set to true, indicates that the size
         * of the key needed is not fixed.
         *
         * The data in here is _most likely_ a key. But may also hold an input vector (IV) or any other
         * data which is needed for a particular algorithm instance.
         */
        struct ArgumentDefinition {
            std::uint64_t size_;        //!< @brief Defines the size in bytes of the key (special meaning for value 0).
            std::string description_;        //!< @brief A description of this input data.
            bool needed_ = false;            //!< @brief States that this key is needed.
        };

        std::string name_;                           //!< @brief The name of this algorithm.
        Family family_;                              //!< @brief The family of the algorithm.
        ArgumentDefinition initial_argument_;        //!< @brief The requirements of the initial key used.
        ArgumentDefinition final_argument_;          //!< @brief The requirements of the final key used.
        std::string description_;                    //!< @brief A human readable description of the algorithm.
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
     * @return  0 if add was ok, else an error in the context of the concrete algorithm implementation.
     */
    int Add(std::string const & text);

    /**
     * @brief   Adds data to the algorithm
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   data        the data to add.
     * @return  0 if add was ok, else an error in the context of the concrete algorithm implementation.
     */
    int Add(std::vector<std::byte> const & data);

    /**
     * @brief   Adds data to the algorithm
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @param   data        the data to add.
     * @param   size        size of the data to add.
     * @return  0 if add was ok, else an error in the context of the concrete algorithm implementation.
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
     * @return  0 if finalize was ok, else an error in the context of the concrete algorithm implementation.
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
     * @return  0 if finalize was ok, else an error in the context of the concrete algorithm implementation.
     */
    int Finalize(std::vector<std::byte> & result, char const * data, std::uint64_t size);

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     * */
    Description const & GetDescription() const;

    /**
     * @brief   Initialize this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * The object **WILL NOT** be initialized twice.
     * @param   data        the initial data (== initial key) to use, if any
     * @return  0 if initialize was ok, else an error in the context of the concrete algorithm implementation.
     */
    int Initialize(std::vector<std::byte> const & data = {});

    /**
     * @brief   Initialize this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * The object **WILL NOT** be initialized twice.
     * @param   data        the initial data (== initial key) to use, if any
     * @param   size        size of the data used for initialization.
     * @return  0 if initialize was ok, else an error in the context of the concrete algorithm implementation.
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
     * @return  0 if add was ok, else an error.
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
     * @return  0 if finalize was ok, else an error.
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
