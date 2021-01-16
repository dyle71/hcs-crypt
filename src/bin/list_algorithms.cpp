/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */


#include <string>

#include <headcode/crypt/crypt.hpp>

#include "list_algorithms.hpp"


void ListAlgorithms(std::ostream & out) {

    for (auto family : {headcode::crypt::Family::SYMMETRIC_CIPHER, headcode::crypt::Family::HASH}) {

        out << headcode::crypt::GetFamilyText(family) << "\n";
        auto algorithms = headcode::crypt::Factory::GetAlgorithmDescriptions();
        for (auto const & [name, description] : algorithms) {
            if (description.family_ == family) {
                out << "    " << name << "\n";
            }
        }

        out << std::endl;
    }
}
