/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <chrono>
#include <cstdint>
#include <iostream>

#include <gtest/gtest.h>

#include <headcode/benchmark/benchmark.hpp>
#include <headcode/mem/mem.hpp>
#include <headcode/crypt/crypt.hpp>

#include <shared/ipsum_lorem.hpp>


TEST(Benchmark_OPENSSLSHA256, OPENSSLSHA256StdString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("openssl-sha256");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha256");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is with padding
        algo->Add(kIpsumLoremText);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * kIpsumLoremText.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark OpenSSLSHA256::OPENSSLSHA256StdString ");

    auto expected = std::string{"987471f3d737a2a78c6e30d15e1ee304d15c3103f5035083484bb47e60962682"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_OPENSSLSHA256, OPENSSLSHA256CArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("openssl-sha256");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha256");

    auto block_incoming = kIpsumLoremText.c_str();
    auto size_incoming = std::strlen(block_incoming);
    std::uint64_t size_outgoing = 0ul;

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is without padding
        algo->Add(reinterpret_cast<unsigned char const *>(block_incoming), size_incoming, nullptr, size_outgoing);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * size_incoming};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark OpenSSLSHA256::OPENSSLSHA256CArray ");

    auto expected = std::string{"1ea8106595cc961d258251ad51613694c625c080e1103f1b8c5c5ed411b70de5"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
