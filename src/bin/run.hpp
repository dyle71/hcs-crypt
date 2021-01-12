/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.  
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_RUN_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_RUN_HPP

#include "cli.hpp"


/**
 * @brief   Exeuctes the program
 * @param   config          the config supplied
 * @return  exit code
 */
int Run(CryptoClientArguments const & config);


#endif
