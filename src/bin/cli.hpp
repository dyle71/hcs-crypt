/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_CLI_HPP

#include <string>


/**
 * @brief   The crypto client configuration.
 */
struct CryptoClientArguments {
    std::string command_;           //!< @brief Crypto command to process.
};


/**
 * @brief   Parses the command line elements.
 * @param   argc    as for main()
 * @param   argv    as for main()
 */
CryptoClientArguments ParseCommandLine(int argc, char ** argv);


#endif
