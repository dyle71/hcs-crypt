# ------------------------------------------------------------
# This file is part of crypt of headcode.space
#
# The 'LICENSE.txt' file in the project root holds the software license.
# Copyright (C) 2020-2021 headcode.space e.U.  
# Oliver Maurhart <info@headcode.space>, https://www.headcode.space
# ------------------------------------------------------------

include_directories(${CMAKE_SOURCE_DIR}/include)

set(CRYPT_SRC
    start.cpp
    cli.cpp
    explain_algorithm.cpp
    list_algorithms.cpp
    main.cpp
    run.cpp
)

add_executable(crypt ${CRYPT_SRC})
target_link_libraries(crypt "hcs-crypt;${CMAKE_REQUIRED_LIBRARIES}")
install(TARGETS crypt RUNTIME DESTINATION bin)
