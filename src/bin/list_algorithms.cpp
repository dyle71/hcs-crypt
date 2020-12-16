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

#include <headcode/crypt/crypt.hpp>

#include "list_algorithms.hpp"

using namespace headcode::crypt;


/**
 * @brief   Returns the width of the current terminal.
 * @return  The width of the current terminals in characters.
 */
int GetTerminalWidth() {
#ifdef __linux__
    struct winsize w;
    ioctl(0, TIOCGWINSZ, &w);
    return w.ws_col;
#endif
}


/**
 * @brief   Simple, short listening of algorithms.
 * @param   out             stream to dump to.
 * @param   algorithms      name and description mapping.
 */
void ListAlgorithmsSimple(std::ostream & out, std::map<std::string, Algorithm::Description> const & algorithms) {

    for (auto const & pair : algorithms) {
        out << "    " << pair.first << "\n";
    }
}


/**
 * @brief   Verbose, extened listening of algorithms.
 * @param   out             stream to dump to.
 * @param   algorithms      name and description mapping.
 */
void ListAlgorithmsVerbose(std::ostream & out, std::map<std::string, Algorithm::Description> const & algorithms) {

    // all verbose column headers
    static std::string const column_header_name{"name"};
    static std::string const column_header_description{"description"};

    // collect the maximum column widths
    struct {
        int max_name_ = column_header_name.size();
        int max_description_ = column_header_description.size();
    } column_max_width;

    for (auto const & pair : algorithms) {
        column_max_width.max_name_ = std::max<int>(pair.first.size(), column_max_width.max_name_);
        column_max_width.max_description_ =
                std::max<int>(pair.second.description_.size(), column_max_width.max_description_);
    }

    // divide the available space
    unsigned int max_width = GetTerminalWidth();
    auto available_width = max_width - 1;

    // output
    for (auto const & pair : algorithms) {
        out << std::setw(column_max_width.max_name_) << pair.first
            << " "
            << std::setw(column_max_width.max_description_) << pair.second.description_
            << "\n";
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
