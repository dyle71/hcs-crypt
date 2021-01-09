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

#include <headcode/crypt/factory.hpp>

#include "register.hpp"

using namespace headcode::crypt;


/**
 * @brief   Our algorithm registry.
 * The is the "database" of all known algortihm producers.
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

    // DCLP not on singleton instance (since due to C++11 static standard behavior this is thread-safe)
    // ... but on loading the registry with all known algorithms.
    if (!registry.initialized_) {
        static std::mutex initialize_mutex;
        std::lock_guard<std::mutex> lock(initialize_mutex);
        if (!registry.initialized_) {
            registry.initialized_ = true;
            RegisterKnownAlgorithms();
        }
    }
    return registry;
}


std::unique_ptr<Algorithm> Factory::Create(std::string const & name) {

    auto & registry = GetRegistryInstance();
    std::shared_ptr<Factory::Producer> producer;

    {
        std::lock_guard<std::mutex> lock(registry.mutex_);

        auto iter = registry.producer_registry_.find(name);
        if (iter == registry.producer_registry_.end()) {
            return nullptr;
        }

        producer = std::get<1>(iter->second);
    }

    if (producer == nullptr) {
        return nullptr;
    }
    return (*producer)();
}


std::map<std::string, Algorithm::Description> Factory::GetAlgorithmDescriptions(Family family) {

    // TODO: optimize this for lazy loading

    auto & registry = GetRegistryInstance();

    std::map<std::string, Algorithm::Description> res;
    {
        std::lock_guard<std::mutex> lock(registry.mutex_);
        for (auto const & p : registry.producer_registry_) {
            if (std::get<0>(p.second) == family) {
                std::shared_ptr<Factory::Producer> const & producer = std::get<1>(p.second);
                res.emplace(p.first, producer->GetDescription());
            }
        }
    }

    return res;
}


void Factory::Register(std::string const & name, Family family, std::shared_ptr<Factory::Producer> producer) {
    auto & registry = GetRegistryInstance();
    std::lock_guard<std::mutex> lock(registry.mutex_);
    registry.producer_registry_[name] = std::make_tuple(family, std::move(producer));
}
