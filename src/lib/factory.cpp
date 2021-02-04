/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
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
 * The is the "database" of all known algorithm producers.
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
     * @brief   Modification counter.
     */
    std::uint64_t mod_counter_{0};

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

    // Double Check Locking Pattern not on singleton instance
    // (since due to C++11 static standard behavior this is thread-safe)
    // ... but on loading the registry with all known algorithms.
    // TODO: Think of a lock-free alternative to this.
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


std::map<std::string, Algorithm::Description> const & Factory::GetAlgorithmDescriptions() {

    auto & registry = GetRegistryInstance();

    // We try to not enumerate all known algorithms anew each time this
    // method is invoked. Instead, we check, if something has changed in
    // the registry. If not, we return the data we fetched in the past.
    // If some new algorithms have been added (or removed, or something)
    // then the mod_counter_ is different, thus enforcing us to
    // re-fetch the data from the registry.

    static struct {
        std::uint64_t mod_counter_{0};
        std::map<std::string, Algorithm::Description> description_;
    } __attribute__((aligned(64))) cache;

    {
        std::lock_guard<std::mutex> lock(registry.mutex_);
        if (cache.mod_counter_ != registry.mod_counter_) {
            // re-cache algorithm data
            cache.description_.clear();
            for (auto const & p : registry.producer_registry_) {
                std::shared_ptr<Factory::Producer> const & producer = std::get<1>(p.second);
                cache.description_.emplace(p.first, producer->GetDescription());
            }
            cache.mod_counter_ = registry.mod_counter_;
        }
    }

    return cache.description_;
}


void Factory::Register(std::string const & name, Family family, std::shared_ptr<Factory::Producer> producer) {
    auto & registry = GetRegistryInstance();
    std::lock_guard<std::mutex> lock(registry.mutex_);
    registry.producer_registry_[name] = std::make_tuple(family, std::move(producer));
    registry.mod_counter_++;
}
