/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <iostream>

#include "cli.hpp"
#include "list_algorithms.hpp"


int main(int argc, char ** argv) {

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
        ListAlgorithms(std::cout, config.verbose_);
        return 0;
    }

    std::cout << "algorithm: " << config.algorithm_ << std::endl;
    if (config.input_files_.empty()) {
        std::cout << "stdin://" << std::endl;
    } else {
        for (auto const & name : config.input_files_) {
            std::cout << "name: " << name << std::endl;
        }
    }

    return 0;
}
