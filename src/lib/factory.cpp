/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <headcode/crypt/factory.hpp>

#include "register.hpp"

using namespace headcode::crypt;


/**
 * @brief   Our algorithm registry.
 */
static class AlgorithmRegistry {
public:
    /**
     * @brief   Prevent race conditions.
     */
    std::mutex mutex_;

    /**
     * @brief   All known algorithm producers.
     */
    std::map<std::string, std::tuple<Family, std::shared_ptr<Factory::Producer>>> producer_registry_;

    /**
     * @brief   Constructor.
     */
    AlgorithmRegistry() {
        RegisterKnownAlgorithms();
    }

} factory_instance_;


std::shared_ptr<Algorithm> Factory::Create(std::string const & name) {

    std::lock_guard<std::mutex> lock(factory_instance_.mutex_);

    auto iter = factory_instance_.producer_registry_.find(name);
    if (iter == factory_instance_.producer_registry_.end()) {
        return nullptr;
    }

    auto producer = std::get<1>(iter->second);
    if (producer == nullptr) {
        return nullptr;
    }

    return (*producer)();
}


std::set<std::string> Factory::GetAlgorithmNames(Family family) {

    std::lock_guard<std::mutex> lock(factory_instance_.mutex_);

    std::set<std::string> res;
    for (auto const & p : factory_instance_.producer_registry_) {
        if (std::get<0>(p.second) == family) {
            res.insert(p.first);
        }
    }

    return res;
}


void Factory::Register(std::string const & name, Family family, std::shared_ptr<Factory::Producer> producer) {
    std::lock_guard<std::mutex> lock(factory_instance_.mutex_);
    factory_instance_.producer_registry_[name] = std::make_tuple(family, std::move(producer));
}
