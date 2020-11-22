/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <atomic>
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
class Registry {
public:
    /**
     * @brief   Initialized flag. If false, no algorithms have been loaded.
     */
    std::atomic<bool> initialized_ = false;

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
    Registry() = default;

    /**
     * @brief   Copy Constructor.
     */
    Registry(Registry const &) = delete;

    /**
     * @brief   Move Constructor.
     */
    Registry(Registry &&) = delete;

    /**
     * @brief   Destructor
     */
    ~Registry() = default;

    /**
     * @brief   Assignment
     * @return  this
     */
    Registry & operator=(Registry const &) = delete;

    /**
     * @brief   Move Assignment
     * @return  this
     */
    Registry & operator=(Registry &&) = delete;
};


/**
 * @brief   Returns the Registry singleton.
 * @return  The one and only registry instance.
 */
static Registry & GetRegistryInstance() {

    static Registry registry;
    if (!registry.initialized_) {

        // avoid race conditions on double init calls
        static std::mutex initialize_mutex;
        std::lock_guard<std::mutex> lock(initialize_mutex);
        if (!registry.initialized_) {
            registry.initialized_ = true;
            RegisterKnownAlgorithms();
        }
    }
    return registry;
}


std::shared_ptr<Algorithm> Factory::Create(std::string const & name) {

    auto & registry = GetRegistryInstance();
    std::lock_guard<std::mutex> lock(registry.mutex_);

    auto iter = registry.producer_registry_.find(name);
    if (iter == registry.producer_registry_.end()) {
        return nullptr;
    }

    auto producer = std::get<1>(iter->second);
    if (producer == nullptr) {
        return nullptr;
    }

    return (*producer)();
}


std::set<std::string> Factory::GetAlgorithmNames(Family family) {

    auto & registry = GetRegistryInstance();
    std::lock_guard<std::mutex> lock(registry.mutex_);

    std::set<std::string> res;
    for (auto const & p : registry.producer_registry_) {
        if (std::get<0>(p.second) == family) {
            res.insert(p.first);
        }
    }

    return res;
}


void Factory::Register(std::string const & name, Family family, std::shared_ptr<Factory::Producer> producer) {
    auto & registry = GetRegistryInstance();
    std::lock_guard<std::mutex> lock(registry.mutex_);
    registry.producer_registry_[name] = std::make_tuple(family, std::move(producer));
}
