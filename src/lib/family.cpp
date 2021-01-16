/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <cassert>
#include <map>

#include <headcode/crypt/family.hpp>


std::string const & headcode::crypt::GetFamilyText(headcode::crypt::Family family) {

    static std::map<headcode::crypt::Family, std::string> const known_family_texts = {
            {headcode::crypt::Family::SYMMETRIC_CIPHER, "Symmetric Ciphers"},
            {headcode::crypt::Family::HASH, "Hashes"},
            {headcode::crypt::Family::UNKNOWN, "Unknown Family"}};

    auto iter = known_family_texts.find(family);
    assert(iter != known_family_texts.end());
    return iter->second;
}
