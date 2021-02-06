/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>

#include <gtest/gtest.h>

#include <headcode/benchmark/benchmark.hpp>
#include <headcode/crypt/crypt.hpp>

#include <shared/ipsum_lorem.hpp>


TEST(Benchmark_Copy, CopyStdString1000) {

    auto loop_count = 10'000u;

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "copy");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        algo->Add(kIpsumLoremText);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * kIpsumLoremText.size()};

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkCopy::CopyStdString1000 ");
}


TEST(Benchmark_Copy, CopyCArray1000) {

    auto loop_count = 10'000u;

    auto algo = headcode::crypt::Factory::Create("copy");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "copy");

    auto block_incoming = kIpsumLoremText.c_str();
    auto size_incoming = std::strlen(block_incoming);
    auto block_outgoing = new unsigned char[size_incoming];
    auto size_outgoing = size_incoming;

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        algo->Add(reinterpret_cast<unsigned char const *>(block_incoming), size_incoming, block_outgoing, size_outgoing);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * size_incoming};

    delete [] block_outgoing;

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkCopy::CopyCArray1000 ");
}
