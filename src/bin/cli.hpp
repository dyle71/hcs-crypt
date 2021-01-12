/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP

#include <cstdio>
#include <list>
#include <string>


/**
 * @brief   The crypto client configuration.
 */
struct CryptoClientArguments {

    std::string error_string_;                  //!< @brief Error encountered while parsing.
    std::string algorithm_;                     //!< @brief Algorithm to use.
    bool hex_output_ = false;                   //!< @brief Output as hexadecimal ASCII charcter string.
    bool list_algorithms_ = false;              //!< @brief List all known algorithms.
    bool proceed_ = false;                      //!< @brief Proceed and run a particular algorithm or stop.
    bool verbose_ = false;                      //!< @brief Verbosity flag.
    bool version_ = false;                      //!< @brief Show version.
    std::list<std::string> input_files_;        //!< @brief All the input files (if size() == 0 ==> use stdin).
    FILE * output_ = stdout;                    //!< @brief The output stream to write to.
    bool multiline_output_ = false;             //!< @brief List output file by file. True, for more than 1 input file.

    /**
     * @brief   Checks if the given configuration is ok.
     * @return  True, if we have a valid configuration.
     */
    bool IsConfigOk() const {
        return error_string_.empty();
    }

} __attribute__((aligned(128)));


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


/**
 * @brief   Checks if the given algorithm name exists.
 * @param   algorithm       the algorithm name to check.
 * @return  true, if it exists.
 */
bool VerifyAlgorithm(std::string const & algorithm);


#endif
