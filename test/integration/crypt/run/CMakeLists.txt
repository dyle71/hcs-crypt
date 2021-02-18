# ------------------------------------------------------------
# This file part of hcs-crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020-2021 headcode.space e.U.
# Oliver Maurhart <info@headcode.space>, https://www.headcode.space
# ------------------------------------------------------------

configure_file(test.py ${CMAKE_CURRENT_BINARY_DIR}/test.py @ONLY)

string(LENGTH "${CMAKE_SOURCE_DIR}/test/" CMAKE_SOURCE_DIR_LENGTH)
string(SUBSTRING ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR_LENGTH} -1 CURRENT_TEST_NAME)
add_test(${CURRENT_TEST_NAME} ${CMAKE_CURRENT_BINARY_DIR}/test.py)
