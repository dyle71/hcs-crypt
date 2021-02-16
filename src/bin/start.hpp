/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_CRYPT_START_HPP
#define HEADCODE_SPACE_CRYPT_CRYPT_START_HPP

#include <istream>
#include <ostream>


/**
 * @brief   This is the beginning of all.
 * This is a defered main() to enable unit testing.
 * @param   argc        command line argument string count.
 * @param   argv        command line argument string.
 * @param   in          input stream
 * @param   out         output data stream
 * @param   err         error data stream
 * @return  exitcode of program.
 */
int Start(int argc, char ** argv, std::istream & in, std::ostream & out, std::ostream & err);


#endif
