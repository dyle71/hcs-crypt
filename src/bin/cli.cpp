/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <argp.h>

#include <iostream>
#include <set>
#include <string>

#include "cli.hpp"

#define PROGRAM_VERSION         "crypt v" VERSION

#define PROGRAM_DOCUMENTATION   "crypt -- a cryptography command line client.\n\
\n\
COMMAND is one of {encrypt, decrypt, hash}. If FILE\n\
is ommited then stdin is read.\n\
\n\
OPTIONS:\n\
"


/**
 * @brief   All essential ARGP data.
 */
struct ARGPData {

    /**
     * @brief   ARGP: well known program version string.
     */
    char const * argp_program_version = PROGRAM_VERSION;

    /**
     * @brief   ARGP: well known bug email address.
     */
    char const * argp_program_bug_address = "https://gitlab.com/headcode.space/crypt/-/issues";

    /**
     * @brief   ARGP: documentation.
     */
    char const * argp_documentation = PROGRAM_DOCUMENTATION;

    /**
     * @brief   ARGP: arguments.
     */
    char const * argp_arguments = "COMMAND [FILE]";

} argp_data_;


/**
 * @brief   ARGP: options.
 */
static struct argp_option options_[] = {
    {"version", 'v', 0, 0, "Show version.", 0},
    { 0, 0, 0, 0, 0, 0}
};


/**
 * @brief   Shows the current program version.
 */
void ShowVersion() {
    std::cout << PROGRAM_VERSION << std::endl;
}


/**
 * @brief   ARGP: parse a single option callback.
 * @param   key     current key.
 * @param   arg     argument to the key.
 * @param   state   argp parser state.
 * @return  0 if ok, ARGP_ERROR_* else.
 */
static error_t ParseOption(int key, char * arg, struct argp_state * state) {

    auto arguments = static_cast<CryptoClientArguments *>(state->input);

    switch (key) {

        case 'v':
            ShowVersion();
            std::exit(0);
            break;

        case ARGP_KEY_ARG:

            if (state->arg_num == 0) {
                arguments->command_ = arg;
            }
            if (state->arg_num > 1) {
                argp_usage(state);
            }
            break;

        case ARGP_KEY_END:
            if (state->arg_num < 1) {
                argp_usage(state);
            }
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}


CryptoClientArguments ParseCommandLine(int argc, char ** argv) {

    argp argp_configuration = {options_,
                               ParseOption,
                               argp_data_.argp_arguments,
                               argp_data_.argp_documentation,
                               0, 0, 0};

    CryptoClientArguments res;
    argp_parse(&argp_configuration, argc, argv, 0, 0, &res);

    static std::set<std::string> const valid_commands = {"encrypt", "decrypt", "hash"};
    if (valid_commands.find(res.command_) == valid_commands.end()) {
        std::cerr << "Unknown command. Type --help for help." << std::endl;
        std::exit(255);
    }

    return res;
}
