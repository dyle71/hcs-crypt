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


TEST(Benchmark_LTCTIGER192, LTCTIGER192StdString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-tiger192");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-tiger192");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        algo->Add(IPSUM_LOREM_TEXT);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCTIGER192::LTCTIGER192StdString ");

    auto expected = std::string{"abd09dd41fe994a53b3367eb336a37e0435df3d189beee88"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_LTCTIGER192, LTCTIGER192CArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-tiger192");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-tiger192");

    auto array = IPSUM_LOREM_TEXT.c_str();
    auto size = std::strlen(array);

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        algo->Add(array, size);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * size};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCTIGER192::LTCTIGER192CArray ");

    auto expected = std::string{"abd09dd41fe994a53b3367eb336a37e0435df3d189beee88"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
