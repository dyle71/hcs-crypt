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
#include <string_view>
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
static void CollectAlgorithmRows(std::map<std::string, AlgorithmRow> & row,
                                 std::map<std::string, Algorithm::Description> const & algorithms) {

    for (const auto & [name, description] : algorithms) {
        row.emplace(name, AlgorithmRow{name, description});
    }
}


/**
 * @brief   Collect all maximum width of all algorithm row columns.
 * @param   maximim_column_width        The vector holding maximum width with each AlgorithmRow::Column.
 * @param   row                         All the algorithm rows.
 */
static void CollectAlgorithmColumnWidths(std::vector<unsigned int> & maximim_column_width,
                                         std::map<std::string, AlgorithmRow> const & row) {

    maximim_column_width.resize(AlgorithmRow::GetColumnCount());
    for (unsigned int column = 0; column < maximim_column_width.size(); ++column) {
        maximim_column_width[column] = AlgorithmRow::GetColumnHeader(static_cast<AlgorithmRow::Column>(column)).size();
    }

    for (auto const & pair : row) {
        auto const & algorithm = pair.second;
        for (unsigned int column = 0; column < maximim_column_width.size(); ++column) {
            auto const & column_text = algorithm.GetColumn(static_cast<AlgorithmRow::Column>(column));
            maximim_column_width[column] = std::max<unsigned int>(column_text.size(), maximim_column_width[column]);
        }
    }
}


/**
 * @brief   Gets the column delimiter
 * @return  the delimiter used in verbose mode between the columns
 */
static std::string const & GetColumnDelimiter() {
    static std::string delimiter{"   "};
    return delimiter;
}


/**
 * @brief   Prints a single algorithm row
 * @param   out                 The stream to print to.
 * @param   row                 The row to print.
 * @param   column_width        The maximum column widths.
 */
static void ListAlgorithmRow(std::ostream & out,
                             AlgorithmRow const & row,
                             std::vector<unsigned int> const & column_width) {

    for (unsigned int i = 0; i < AlgorithmRow::GetColumnCount(); ++i) {

        if (i != 0) {
            out << GetColumnDelimiter();
        }

        auto column = static_cast<AlgorithmRow::Column>(i);
        out << std::left << std::setw(column_width[i]) << row.GetColumn(column);
    }

    out << std::endl;
}


/**
 * @brief   Simple, short listening of algorithms.
 * @param   out             stream to dump to.
 * @param   algorithms      name and description mapping.
 */
static void ListAlgorithmsSimple(std::ostream & out, std::map<std::string, Algorithm::Description> const & algorithms) {

    for (auto const & pair : algorithms) {
        out << "    " << pair.second.name_ << "\n";
    }
}


/**
 * @brief   Prints a repitition of '-' spanning a whole line.
 * @param   out             the stream to print to.
 * @param   column_width    all the known columns.
 */
static void PrintSpanningLine(std::ostream & out, std::vector<unsigned int> const & column_width) {

    unsigned int length = 0;
    std::for_each(column_width.begin(), column_width.end(), [&](auto width) { length += width; });
    length += (column_width.size() - 1) * GetColumnDelimiter().size();
    out << std::string(length, '-') << std::endl;
}


/**
 * @brief   Verbose, extened listening of algorithms.
 * @param   out             stream to dump to.
 * @param   trim            shorten columns on output.
 * @param   algorithms      name and description mapping.
 */
static void ListAlgorithmsVerbose(std::ostream & out,
                                  std::map<std::string, Algorithm::Description> const & algorithms) {

    std::map<std::string, AlgorithmRow> rows;
    CollectAlgorithmRows(rows, algorithms);

    std::vector<unsigned int> max_column_width;
    CollectAlgorithmColumnWidths(max_column_width, rows);

    AlgorithmRow header;
    ListAlgorithmRow(out, header, max_column_width);
    PrintSpanningLine(out, max_column_width);
    for (auto & [_, row] : rows) {
        ListAlgorithmRow(out, row, max_column_width);
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
