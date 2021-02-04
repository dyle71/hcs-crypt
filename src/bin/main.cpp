/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <iostream>

#include "cli.hpp"
#include "explain_algorithm.hpp"
#include "list_algorithms.hpp"
#include "run.hpp"


int main(int argc, char ** argv) {
    
    // TODO: Drop to seccomp: https://en.wikipedia.org/wiki/Seccomp

    auto config = ParseCommandLine(argc, argv);
    if (!config.IsConfigOk()) {
        std::cerr << "Error parsing command line: " << config.error_string_ << std::endl;
        std::cerr << "Type -h or --help for help." << std::endl;
        return 255;
    }

    if (config.version_) {
        ShowVersion();
        return 0;
    }

    if (config.list_algorithms_) {
        ListAlgorithms(std::cout);
        return 0;
    }

    if (config.explain_algorithm_) {
        ExplainAlgorithm(std::cout, config.algorithm_);
        return 0;
    }

    return Run(config);
}
