/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_ALGORITHM_ROW_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_ALGORITHM_ROW_HPP

#include <list>
#include <string>

#include <headcode/crypt/algorithm.hpp>


/**
 * @brief   A single row of all the data an algorithm can offer.
 */
class AlgorithmRow {

    std::string name_;
    std::string alias_;
    std::string family_;
    std::string source_;
    std::string description_;
    std::string initialziation_size_;
    std::string initialziation_description_;
    std::string finalization_size_;
    std::string finalization_description_;

public:

    /**
     * @brief   The columns we on verbose
     */
    enum class Column : unsigned int {
        NAME = 0,                          //!< @brief Name of the algorithm.
        ALIAS,                             //!< @brief Name this algorithm is an alias of.
        FAMILY,                            //!< @brief Algorithm family.
        SOURCE,                            //!< @brief Point of origin (library).
        DESCRIPTION,                       //!< @brief Algorithm Description.
        INITIALIZATION_DESCRIPTION,        //!< @brief Description of the init data.
        INITIALIZATION_SIZE,               //!< @brief Block size of the init in bytes.
        FINALIZATION_DESCRIPTION,          //!< @brief Description of the finalization data.
        FINALIZATION_SIZE                  //!< @brief Block size of the finalization data in bytes.
    };

    /**
     * @brief   Constructor
     * @param   name                        name of the algorithm.
     * @param   algorithm_description       the algorithm description.
     */
    AlgorithmRow(std::string name, headcode::crypt::Algorithm::Description const & algorithm_description);

    /**
     * @brief   Copy Constructor.
     */
    AlgorithmRow(AlgorithmRow const &) = default;

    /**
     * @brief   Move Constructor.
     */
    AlgorithmRow(AlgorithmRow &&) = default;

    /**
     * @brief   Destructor.
     */
    ~AlgorithmRow() = default;

    /**
     * @brief   Assignment.
     * @return  this.
     */
    AlgorithmRow & operator=(AlgorithmRow const &) = default;

    /**
     * @brief   Move Assignment.
     * @return  this.
     */
    AlgorithmRow & operator=(AlgorithmRow &&) = default;

    /**
     * @brief   Gets the alias of the algorithm.
     * @return  The alias of the algorithm.
     */
    std::string const & GetAlias() const {
        return alias_;
    }

    /**
     * @brief   Gets a algorithm data particle.
     * @param   column      idnetifies the data requested.
     * @return  the data.
     */
    std::string const & GetColumn(Column column) const;

    /**
     * @brief   Gets the description of the algorithm.
     * @return  The description of the algorithm.
     */
    std::string const & GetDescription() const {
        return description_;
    }

    /**
     * @brief   Gets the family description of the algorithm.
     * @return  The family description of the algorithm.
     */
    std::string const & GetFamily() const {
        return family_;
    }

    /**
     * @brief   Gets the description of the final data of the algorithm.
     * @return  The description of the final data of the algorithm.
     */
    std::string const & GetFinalizationDescription() const {
        return finalization_description_;
    }

    /**
     * @brief   Gets the size of the final data of the algorithm.
     * @return  The size of the final data of the algorithm.
     */
    std::string const & GetFinalizationSize() const {
        return finalization_size_;
    }

    /**
     * @brief   Gets the description of the init data of the algorithm.
     * @return  The description of the init data of the algorithm.
     */
    std::string const & GetInitialziationDescription() const {
        return initialziation_description_;
    }

    /**
     * @brief   Gets the size of the init data of the algorithm.
     * @return  The size of the init data of the algorithm.
     */
    std::string const & GetInitialziationSize() const {
        return initialziation_size_;
    }

    /**
     * @brief   Gets the name of the algorithm.
     * @return  The name of the algorithm.
     */
    std::string const & GetName() const {
        return name_;
    }

    /**
     * @brief   Gets the source library of the algorithm.
     * @return  The source library of the algorithm.
     */
    std::string const & GetSource() const {
        return source_;
    }
};


#endif
