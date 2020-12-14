/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP

#include <stdexcept>
#include <string>


/**
 * @brief   The crypto client configuration.
 */
struct CryptoClientArguments {
    std::string error_string_;        //!< @brief Error encountered while parsing.
    std::string command_;             //!< @brief Crypto command to process.
    bool proceed_ = false;            //!< @brief Show version.
    bool version_ = false;            //!< @brief Show version.

    /**
     * @brief   Checks if the given configuration is ok.
     * @return  True, if we have a valid configuration.
     */
    bool IsConfigOk() const {
        return error_string_.empty();
    }
};


/**
 * @brief   Parses the command line elements.
 * @param   argc    as for main()
 * @param   argv    as for main()
 */
CryptoClientArguments ParseCommandLine(int argc, char ** argv);


/**
 * @brief   Show the program version.
 */
void ShowVersion(std::ostream & out = std::cout);


#endif
