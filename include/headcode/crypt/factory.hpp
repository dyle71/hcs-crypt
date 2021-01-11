/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_FACTORY_HPP
#define HEADCODE_SPACE_CRYPT_FACTORY_HPP


#include <map>
#include <memory>
#include <string>

#include "algorithm.hpp"
#include "family.hpp"


namespace headcode::crypt {


/**
 * @brief   The Algorithm factory.
 */
class Factory {

public:
    /**
     * @brief   Each concrete algorithm declares a dedicated Producer.
     * The factory does not manage algorithm instances but producer instances,
     * which in turn create new algorithm objects on demand.
     * Every algorithm has to declare its (proper) Producer class.
     */
    class Producer {
    public:
        /**
         * @brief   Call operator - creates the algorithm.
         * @return  A new algorithm instance.
         */
        virtual std::unique_ptr<Algorithm> operator()() const = 0;

        /**
         * @brief   Gets the algorithm description.
         * @return  A structure describing the algorithm.
         */
        virtual Algorithm::Description const & GetDescription() const = 0;
    };

    /**
     * @brief   Constructor.
     */
    Factory() = delete;

    /**
     * @brief   Copy Constructor.
     */
    Factory(Factory const &) = delete;

    /**
     * @brief   Move Constructor.
     */
    Factory(Factory &&) = delete;

    /**
     * @brief   Destructor.
     */
    ~Factory() = delete;

    /**
     * @brief   Assignment.
     * @return  this.
     */
    Factory & operator=(Factory const &) = delete;

    /**
     * @brief   Move Assignment.
     * @return  this.
     */
    Factory & operator=(Factory &&) = delete;

    /**
     * @brief   Create an instance of a specific algorithm.
     * @param   name        the name of the algorithm to create.
     * @return  A shared pointer pointing to an object (which may be nullptr in case of failure).
     */
    static std::unique_ptr<Algorithm> Create(std::string const & name);

    /**
     * @brief   Gets a list of all known algorithms and their descriptions.
     * @return  A list of all algorithms which can be instantiated incl. their descriptions.
     */
    static std::map<std::string, Algorithm::Description> const & GetAlgorithmDescriptions();

    /**
     * @brief   Registers a producer, which can create algorithm instance of a specific name and family.
     * @param   name        the name of the algorithm to be registered.
     * @param   family      the family to which the algorithm belongs to.
     * @param   producer    the Producer instance.
     */
    static void Register(std::string const & name, Family family, std::shared_ptr<Factory::Producer> producer);
};


}


#endif
