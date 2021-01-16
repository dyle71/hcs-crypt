/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */


#include <sstream>
#include <string>

#include <headcode/crypt/crypt.hpp>

#include "explain_algorithm.hpp"


/**
 * @brief   Gets a text describing the block size or "n/a" if the size is 0 or ambiguous
 * @param   size            the size of the block.
 * @return  A text describing the blokc size
 */
static std::string GetBlockSizeText(std::uint64_t size) {
    if (size != 0) {
        return std::to_string(size) + " Bytes";
    }
    return std::string{"n/a"};
}


/**
 * @brief   Gets a text describing the found arguments.
 * @param   arguments       the arguments of some parts of the algorithm.
 * @param   indent          the indention of each line.
 * @return  A text describing the arguments.
 */
static std::string GetArgumentList(
        std::map<std::string, headcode::crypt::Algorithm::Description::ArgumentDefinition> const & arguments,
        std::string const & indent = "    ") {

    if (arguments.empty()) {
        return std::string{"n/a"};
    }

    std::stringstream ss;
    for (auto const & [name, definition] : arguments) {
        ss << indent << "Name: " << name << std::endl;
        ss << indent << indent << "Description: " << definition.description_ << std::endl;
        ss << indent << indent << "Size: " << GetBlockSizeText(definition.size_) << std::endl;
        ss << indent << indent
           << "Padding strategy: " << headcode::crypt::GetPaddingStrategyText(definition.padding_strategy_)
           << std::endl;
        ss << indent << indent << "Mandatory: " << (definition.optional_ ? "no" : "yes") << std::endl;
    }

    return ss.str();
}


void ExplainAlgorithm(std::ostream & out, std::string const & name) {

    auto algorithm = headcode::crypt::Factory::Create(name);
    if (!algorithm) {
        out << "Unknown algorithm with this name." << std::endl;
        return;
    }

    auto const & description = algorithm->GetDescription();
    out << "Name: " << description.name_ << std::endl;
    out << "Family: " << headcode::crypt::GetFamilyText(description.family_) << std::endl;
    out << "Brief: " << description.description_short_ << std::endl;
    out << "Description: " << description.description_long_ << std::endl;
    out << "Provided by: " << description.provider_ << std::endl;

    out << "Size of each input block per round: " << GetBlockSizeText(description.block_size_incoming_) << std::endl;
    out << "Size of each output block per round: " << GetBlockSizeText(description.block_size_outgoing_) << std::endl;
    out << "Default input padding strategy: "
        << headcode::crypt::GetPaddingStrategyText(description.block_padding_strategy_) << std::endl;
    out << "Size of final result: " << GetBlockSizeText(description.result_size_) << std::endl;

    out << "Initializing arguments: ";
    auto const & init_arguments = description.initialization_argument_;
    if (init_arguments.empty()) {
        out << "n/a" << std::endl;
    } else {
        out << std::endl << GetArgumentList(description.initialization_argument_);
    }

    out << "Finalizing arguments: ";
    auto const & final_arguments = description.finalization_argument_;
    if (final_arguments.empty()) {
        out << "n/a" << std::endl;
    } else {
        out << std::endl << GetArgumentList(description.finalization_argument_);
    }
}
