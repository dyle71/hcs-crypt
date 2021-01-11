/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020 headcode.space
 * https://www.headcode.space, <info@headcode.space>
 */

#include <chrono>
#include <cstdint>
#include <iostream>

#include <gtest/gtest.h>

#include <headcode/benchmark/benchmark.hpp>
#include <headcode/mem/mem.hpp>
#include <headcode/crypt/crypt.hpp>

#include <shared/ipsum_lorem.hpp>


TEST(Benchmark_LTCRIPEMD256, LTCRIPEMD256StdString1000) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd256");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd256");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        algo->Add(IPSUM_LOREM_TEXT);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkLTCRIPEMD256::LTCRIPEMD256StdString1000 ");

    auto expected = std::string{"4202b1d23944bc07ec1eaf09bf3a600b9734ea484725827f4ee7abf0d8522ddd"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_LTCRIPEMD256, LTCRIPEMD256CArray1000) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd256");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd256");

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

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkLTCRIPEMD256::LTCRIPEMD256CArray1000 ");

    auto expected = std::string{"4202b1d23944bc07ec1eaf09bf3a600b9734ea484725827f4ee7abf0d8522ddd"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
