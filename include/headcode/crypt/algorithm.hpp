/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_ALGORITHM_HPP
#define HEADCODE_SPACE_CRYPT_ALGORITHM_HPP

#include <string>
#include <utility>

#include "family.hpp"


namespace headcode::crypt {


/**
 * @brief   The Algorithm class is the abstract class for any crypto-algorithm.
 */
class Algorithm {

    bool initialized_ = false;        //!< @brief Initialized flag.
    std::string name_;                //!< @brief The name of this algorithm.
    Family family_;                   //!< @brief The family of the algorithm.

public:
    /**
     * @brief   Constructor.
     * @param   name            The name of the algorithm.
     * @param   family          The algorithm family.
     */
    Algorithm(std::string name, Family family) : name_{std::move(name)}, family_{family} {
    }

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
     * @brief   Returns the algorithm family.
     * @return  The family this algorithm belongs to.
     */
    Family GetFamily() const {
        return family_;
    }

    /**
     * @brief   Gets the name of this algorithm instance.
     * @return  The name of this algorithm instance.
     */
    std::string const & GetName() const {
        return name_;
    }

    /**
     * @brief   Initialize this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @return  0 if initialize was ok, else an error.
     */
    int Initialize();

    /**
     * @brief   Checks if this algorithm instance has been initialzed.
     * @return  true, if we init this algorithm object.
     */
    bool IsInitialized() const {
        return initialized_;
    }

private:
    /**
     * @brief   Initialize this object instance.
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     * @return  0 if initialize was ok, else an error.
     */
    virtual int Initialize_() = 0;
};


}


#endif
