/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */


#include <algorithm>
#include <iomanip>
#include <string>
#include <string_view>

#include <headcode/crypt/crypt.hpp>

#include "list_algorithms.hpp"

using namespace headcode::crypt;


/**
 * @brief   Simple, short listening of algorithms.
 * @param   out             stream to dump to.
 * @param   algorithms      name and description mapping.
 * @param   family          filter by this family.
 */
static void ListAlgorithmsSimple(std::ostream & out,
                                 std::map<std::string, Algorithm::Description> const & algorithms,
                                 headcode::crypt::Family family) {

    for (auto const & [name, description] : algorithms) {
        if (description.family_ == family) {
            out << "    " << name << "\n";
        }
    }
}


void ListAlgorithms(std::ostream & out) {

    for (auto family : {headcode::crypt::Family::SYMMETRIC_CIPHER, headcode::crypt::Family::HASH}) {

        out << headcode::crypt::GetFamilyText(family) << "\n";
        auto algorithms = headcode::crypt::Factory::GetAlgorithmDescriptions();
        ListAlgorithmsSimple(out, algorithms, family);

        out << std::endl;
    }
}
