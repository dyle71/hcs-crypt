# ------------------------------------------------------------
# This file is the main CMakeLists of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020-2021 headcode.space e.U.  
# Oliver Maurhart <info@headcode.space>, https://www.headcode.space
# ------------------------------------------------------------

# activate Google Tests
set(GTEST_SOURCE_DIR "${CMAKE_SOURCE_DIR}/3rd/googletest")
include(${CMAKE_SOURCE_DIR}/cmake/gtest.cmake)


# ------------------------------------------------------------ 
# Workload

set(TEST_BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(unit)
add_subdirectory(benchmark)
