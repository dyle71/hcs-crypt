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


TEST(Benchmark_OPENSSLSHA384, OPENSSLSHA384StdString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha384");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is with padding
        algo->Add(kIpsumLoremText);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * kIpsumLoremText.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark OpenSSLSHA384::OPENSSLSHA384StdString ");

    auto expected = std::string{
            "8f3936492400727b3b05bdcd2256d0a0"
            "337c0c2acc55d9da3a51d089cfabe93f"
            "61a80a61fee9937ae6f5ea1547dc899e"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_OPENSSLSHA384, OPENSSLSHA384CArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("openssl-sha384");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "openssl-sha384");

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

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark OpenSSLSHA384::OPENSSLSHA384CArray ");

    auto expected = std::string{
            "814421785ab423b48d9eac99e1a5a075"
            "36eda562e063b91c1452c22ae0e0c79f"
            "ca3747d569091ca4890da01db32b0c71"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
