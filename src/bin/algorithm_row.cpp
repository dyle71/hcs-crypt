/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <map>

#include "algorithm_row.hpp"


AlgorithmRow::AlgorithmRow()
        : name_{"Name"},
          alias_{"Alias"},
          family_{"Family"},
          provider_{"Provider"},
          description_short_{"Short description"},
          description_long_{"Long description"},
          block_incoming_size_{"Input block size"},
          block_outgoing_size_{"Output block size"},
          result_size_{"Result size"},
          initialziation_size_{"Init size"},
          initialziation_description_{"Init description"},
          finalization_size_{"Final size"},
          finalization_description_{"Final description"} {
}


AlgorithmRow::AlgorithmRow(std::string name, headcode::crypt::Algorithm::Description const & algorithm_description)
        : name_{std::move(name)},
          alias_{"ALIAS NOT IMPLEMENTED"},
          family_{GetFamilyText(algorithm_description.family_)},
          provider_{algorithm_description.provider_},
          description_short_{algorithm_description.description_short_},
          description_long_{algorithm_description.description_long_},
          initialziation_size_{std::to_string(algorithm_description.initial_argument_.size_)},
          initialziation_description_{algorithm_description.initial_argument_.description_},
          finalization_size_{std::to_string(algorithm_description.final_argument_.size_)},
          finalization_description_{algorithm_description.final_argument_.description_} {

    if (!algorithm_description.initial_argument_.needed_) {
        initialziation_size_ = "Not needed";
    } else if (algorithm_description.initial_argument_.size_ == 0) {
        initialziation_size_ = "Varies";
    }

    if (!algorithm_description.final_argument_.needed_) {
        finalization_size_ = "Not needed";
    } else if (algorithm_description.final_argument_.size_ == 0) {
        finalization_size_ = "Varies";
    }

    if (algorithm_description.block_size_incoming_ == 0) {
        block_incoming_size_ = "n/a";
    } else {
        block_incoming_size_ = std::to_string(algorithm_description.block_size_incoming_);
    }

    if (algorithm_description.block_size_outgoing_ == 0) {
        block_outgoing_size_ = "n/a";
    } else {
        block_outgoing_size_ = std::to_string(algorithm_description.block_size_outgoing_);
    }

    if (algorithm_description.result_size_ == 0) {
        result_size_ = "n/a";
    } else {
        result_size_ = std::to_string(algorithm_description.result_size_);
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

        case AlgorithmRow::Column::PROVIDER:
            return GetProvider();

        case AlgorithmRow::Column::DESCRIPTION_SHORT:
            return GetShortDescription();

        case AlgorithmRow::Column::DESCRIPTION_LONG:
            return GetLongDescription();

        case AlgorithmRow::Column::BLOCK_SIZE_INCOMING:
            return GetBlockSizeIncoming();

        case AlgorithmRow::Column::BLOCK_SIZE_OUTGOING:
            return GetBlockSizeOutgoing();

        case AlgorithmRow::Column::RESULT_SIZE:
            return GetResultSize();

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


std::string const & AlgorithmRow::GetColumnHeader(Column column) {
    static AlgorithmRow const header;
    return header.GetColumn(column);
}
