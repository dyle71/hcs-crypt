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


int Start(int argc, char ** argv, std::istream & in, std::ostream & out, std::ostream & err) {

    // TODO: Drop to seccomp: https://en.wikipedia.org/wiki/Seccomp

    auto config = ParseCommandLine(argc, argv, in, out, err);
    if (!config.IsConfigOk()) {
        config.err_ << "Error parsing command line: " << config.error_string_ << std::endl;
        config.err_ << "Type -h or --help for help." << std::endl;
        return 255;
    }

    if (config.help_) {
        ShowHelp(config.out_);
        return 0;
    }

    if (config.version_) {
        ShowVersion(config.out_);
        return 0;
    }

    if (config.list_algorithms_) {
        ListAlgorithms(config.out_);
        return 0;
    }

    if (config.explain_algorithm_) {
        ExplainAlgorithm(config.out_, config.algorithm_);
        return 0;
    }

    return Run(config);
}
