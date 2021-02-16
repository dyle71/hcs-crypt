/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP

#include <istream>
#include <ostream>
#include <string>
#include <vector>


/**
 * @brief   The crypto client configuration.
 */
struct CryptoClientArguments {

    std::istream & in_ = std::cin;          //!< @brief Standard input stream.
    std::ostream & out_ = std::cout;        //!< @brief Standard output data stream.
    std::ostream & err_ = std::cerr;        //!< @brief Standard error info stream.

    std::string error_string_;                    //!< @brief Error encountered while parsing.
    std::string algorithm_;                       //!< @brief Algorithm to use.
    bool hex_output_ = false;                     //!< @brief Output as hexadecimal ASCII charcter string.
    bool help_ = false;                           //!< @brief Show help.
    bool explain_algorithm_ = false;              //!< @brief Explain the given algorithm.
    bool list_algorithms_ = false;                //!< @brief List all known algorithms.
    bool version_ = false;                        //!< @brief Show version.
    std::vector<std::string> input_files_;        //!< @brief All the input files (if size() == 0 ==> use stdin).
    bool multiline_output_ = false;        //!< @brief List output file by file. True, for more than 1 input file.

    /**
     * @brief   Constructor.
     * @param   in          standard input stream.
     * @param   out         standard output data stream.
     * @param   err         standard error info stream.
     */
    CryptoClientArguments(std::istream & in, std::ostream & out, std::ostream & err) : in_{in}, out_{out}, err_{err} {
    }

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
 * @param   argc        as for main()
 * @param   argv        as for main()
 * @param   in          input stream
 * @param   out         output data stream
 * @param   err         error data stream
 */
CryptoClientArguments ParseCommandLine(
        int argc, char ** argv, std::istream & in, std::ostream & out, std::ostream & err);


/**
 * @brief   Show the program help.
 * @param   out     stream to push version info.
 */
void ShowHelp(std::ostream & out);


/**
 * @brief   Show the program version.
 * @param   out     stream to push version info.
 */
void ShowVersion(std::ostream & out);


/**
 * @brief   Checks if the given algorithm name exists.
 * @param   algorithm       the algorithm name to check.
 * @return  true, if it exists.
 */
bool VerifyAlgorithm(std::string const & algorithm);


#endif
