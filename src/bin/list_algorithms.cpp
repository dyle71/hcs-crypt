/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */


#ifdef __linux__
#include <sys/ioctl.h>
#else
#error "Need ioctl for terminal width. Unsuppoted platform."
#endif

#include <algorithm>
#include <iomanip>
#include <string>
#include <tuple>

#include <headcode/crypt/crypt.hpp>

#include "algorithm_row.hpp"
#include "list_algorithms.hpp"

using namespace headcode::crypt;


/**
 * @brief   Turns the given set of algorithm data into algorithm rows.
 * @param   row             the final computed set of algorithm rows.
 * @param   algorithms      the set of exsiting algortihms.
 */
static void CollectAlgorithmRows(std::map<std::string, AlgorithmRow> row,
                                 std::map<std::string, Algorithm::Description> const & algorithms) {

    for (const auto & [name, description] : algorithms) {
        row.emplace(name, AlgorithmRow{name, description});
    }
}


/**
 * @brief   Returns the width of the current terminal.
 * @return  The width and height of the current terminals in characters.
 */
static std::tuple<unsigned int, unsigned int> GetTerminalSize() {
#ifdef __linux__
    struct winsize w {};
    ioctl(0, TIOCGWINSZ, &w);
    return std::make_tuple(w.ws_col, w.ws_row);
#endif
}


/**
 * @brief   Simple, short listening of algorithms.
 * @param   out             stream to dump to.
 * @param   algorithms      name and description mapping.
 */
static void ListAlgorithmsSimple(std::ostream & out, std::map<std::string, Algorithm::Description> const & algorithms) {

    for (auto const & [name, _] : algorithms) {
        out << "    " << name << "\n";
    }
}


/**
 * @brief   Verbose, extened listening of algorithms.
 * @param   out             stream to dump to.
 * @param   algorithms      name and description mapping.
 */
static void ListAlgorithmsVerbose(std::ostream & out,
                                  std::map<std::string, Algorithm::Description> const & algorithms) {

    std::map<std::string, AlgorithmRow> row;
    CollectAlgorithmRows(row, algorithms);

    std::vector<unsigned int> max_column_width{AlgorithmRow::GetColumnCount()};
    for (unsigned int column = 0; column < max_column_width.size(); ++column) {
        max_column_width[column] = AlgorithmRow::GetColumnHeader(static_cast<AlgorithmRow::Column>(column)).size();
    }
    
}


void ListAlgorithms(std::ostream & out, bool verbose) {

    for (auto family : {headcode::crypt::Family::CYPHER_SYMMETRIC, headcode::crypt::Family::HASH}) {

        out << headcode::crypt::GetFamilyText(family) << "\n";

        auto algorithms = headcode::crypt::Factory::GetAlgorithmDescriptions(family);
        if (!verbose) {
            ListAlgorithmsSimple(out, algorithms);
        } else {
            ListAlgorithmsVerbose(out, algorithms);
        }

        out << std::endl;
    }
}
