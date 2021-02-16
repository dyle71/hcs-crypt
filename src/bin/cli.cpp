/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */


#include <iostream>

#include <cxxopts.hpp>

#include <headcode/crypt/crypt.hpp>

#include "cli.hpp"

#define PROGRAM_DOCUMENTATION \
"[OPTIONS] ALGORITHM [FILE...]\n\
\n\
ALGORITHM is one of the list of known algorithms. Type --list \n\
to get the list of known algorithms supported. \n\
If FILE is ommited then stdin is read. If more than one FILE is \n\
processed, than the output is multilined and hex.\n\
\n\
Note also, that depending on the algorithm the input and therefore \n\
the output may be padded to fit into an algorithm block size definition.\n\
\n\
Call '--explain' with an algorithm to check the details.\n\n\
"


/**
 * @brief   Creates the command line options.
 * @return  the command line options.
 */
static cxxopts::Options CreateCommandLineOptions() {

    cxxopts::Options options("crypt", "A cryptography command line client");

    options.add_options()
            ("explain", "Explain an algorithm.")
            ("list", "List all known algorithms.")
            ("h,help", "Show help.")
            ("x,hex", "Output has hexadecimal ASCII character string.")
            ("multiline", "Forces multiline output.")
            ("version", "Show version.")
            ("a,algorithm", "Algorithm to use.", cxxopts::value<std::string>())
            ("f,files", "Files to process.", cxxopts::value<std::vector<std::string>>());
    options.parse_positional({"algorithm", "files"});
    options.custom_help(PROGRAM_DOCUMENTATION);
    options.positional_help("Options:");

    return options;
}


CryptoClientArguments ParseCommandLine(
        int argc, char ** argv, std::istream & in, std::ostream & out, std::ostream & err) {

    CryptoClientArguments res{in, out, err};

    auto options = CreateCommandLineOptions();
    cxxopts::ParseResult command_line;
    try {
        command_line = options.parse(argc, argv);
    } catch (std::exception & ex) {
        res.error_string_ = ex.what();
        return res;
    }

    res.explain_algorithm_ = command_line.count("explain") > 0;
    res.list_algorithms_ = command_line.count("list") > 0;
    res.multiline_output_ = command_line.count("multiline") > 0;
    res.hex_output_ = command_line.count("hex") > 0;
    res.help_ = command_line.count("help") > 0;
    res.version_ = command_line.count("version") > 0;

    if (command_line.count("algorithm") == 1) {
        res.algorithm_ = command_line["algorithm"].as<std::string>();
    }
    if (command_line.count("files") > 0) {
        res.input_files_ = command_line["files"].as<std::vector<std::string>>();
    }

    bool need_algorithm = !res.version_ && !res.help_ && !res.list_algorithms_;
    if (need_algorithm) {

        if (!VerifyAlgorithm(res.algorithm_)) {
            if (res.algorithm_.empty()) {
                res.error_string_ = "Missing algorithm. Type --list to list all known algorithms.";
            } else {
                res.error_string_ = "Unknown algorithm. Type --list to list all known algorithms.";
            }
        }
    }

    res.multiline_output_ |= res.input_files_.size() > 1;

    return res;
}


void ShowHelp(std::ostream & out) {
    auto options = CreateCommandLineOptions();
    out << options.help() << std::endl;
}


void ShowVersion(std::ostream & out) {
    out << "crypt v" << VERSION << std::endl;
}


bool VerifyAlgorithm(std::string const & algorithm) {

    if (algorithm.empty()) {
        return false;
    }

    auto const & known_algorithms = headcode::crypt::Factory::GetAlgorithmDescriptions();
    auto iter = known_algorithms.find(algorithm);
    if (iter != known_algorithms.end()) {
        return true;
    }

    return false;
}
