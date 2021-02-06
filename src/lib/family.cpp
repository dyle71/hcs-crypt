/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <map>

#include <headcode/logger/logger.hpp>
#include <headcode/crypt/family.hpp>


std::string const & headcode::crypt::GetFamilyText(headcode::crypt::Family family) {

    static std::map<headcode::crypt::Family, std::string> const known_family_texts = {
            {headcode::crypt::Family::kSymmetricCipher, "Symmetric Ciphers"},
            {headcode::crypt::Family::kHash, "Hashes"},
            {headcode::crypt::Family::kUnknown, "Unknown Family"}};

    auto iter = known_family_texts.find(family);
    if (iter == known_family_texts.end()) {
        headcode::logger::Warning{"headcode.crypt"} << "Unknown family code.";
        static std::string const null_string;
        return null_string;
    }

    return iter->second;
}
