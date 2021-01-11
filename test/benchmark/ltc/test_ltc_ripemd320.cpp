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


TEST(Benchmark_LTCRIPEMD320, LTCRIPEMD320StdString1000) {

    auto loop_count = 1'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd320");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd320");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        algo->Add(IPSUM_LOREM_TEXT);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkLTCRIPEMD320::LTCRIPEMD320StdString1000 ");

    auto expected = std::string{"3585ad7d150e1885377111ee6ad6c634576bc6d1ccaaee4676b0f5a3eec4331ac1b1181bdddc50e6"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_LTCRIPEMD320, LTCRIPEMD320CArray1000) {

    auto loop_count = 1'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd320");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd320");

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

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkLTCRIPEMD320::LTCRIPEMD320CArray1000 ");

    auto expected = std::string{"3585ad7d150e1885377111ee6ad6c634576bc6d1ccaaee4676b0f5a3eec4331ac1b1181bdddc50e6"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
