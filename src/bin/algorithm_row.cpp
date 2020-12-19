/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <map>

#include "algorithm_row.hpp"


AlgorithmRow::AlgorithmRow(std::string name, headcode::crypt::Algorithm::Description const & algorithm_description)
        : name_{std::move(name)},
          alias_{"ALIAS NOT IMPLEMENTED"},
          family_{GetFamilyText(algorithm_description.family_)},
          source_{"SOURCE NOT IMPLEMENTED"},
          description_{algorithm_description.description_},
          initialziation_size_{std::to_string(algorithm_description.initial_argument_.size_)},
          initialziation_description_{algorithm_description.initial_argument_.description_},
          finalization_size_{std::to_string(algorithm_description.final_argument_.size_)},
          finalization_description_{algorithm_description.final_argument_.description_} {

    if (!algorithm_description.initial_argument_.needed_) {
    }
}


std::string const & AlgorithmRow::GetColumn(Column column) const {

    switch (column) {
        case AlgorithmRow::Column::NAME:
            return GetName();

        case AlgorithmRow::Column::ALIAS:
            return GetAlias();

        case AlgorithmRow::Column::FAMILY:
            return GetFamily();

        case AlgorithmRow::Column::SOURCE:
            return GetSource();

        case AlgorithmRow::Column::DESCRIPTION:
            return GetDescription();

        case AlgorithmRow::Column::INITIALIZATION_DESCRIPTION:
            return GetInitialziationDescription();

        case AlgorithmRow::Column::INITIALIZATION_SIZE:
            return GetInitialziationSize();

        case AlgorithmRow::Column::FINALIZATION_DESCRIPTION:
            return GetFinalizationDescription();

        case AlgorithmRow::Column::FINALIZATION_SIZE:
            return GetFinalizationSize();
    }

    static std::string const unknown_column{"unknown column"};
    return unknown_column;
}
