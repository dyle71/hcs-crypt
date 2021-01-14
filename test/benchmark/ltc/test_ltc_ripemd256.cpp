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


TEST(Benchmark_LTCRIPEMD256, LTCRIPEMD256StdString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd256");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd256");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is with padding
        algo->Add(IPSUM_LOREM_TEXT);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCRIPEMD256::LTCRIPEMD256StdString ");

    auto expected = std::string{"baa2bfafa991548084d0f5ce313e4d2a21164bbc11906e5c70bf9ee1f8389a13"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_LTCRIPEMD256, LTCRIPEMD256CArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-ripemd256");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-ripemd256");

    auto block_incoming = IPSUM_LOREM_TEXT.c_str();
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

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCRIPEMD256::LTCRIPEMD256CArray ");

    auto expected = std::string{"4202b1d23944bc07ec1eaf09bf3a600b9734ea484725827f4ee7abf0d8522ddd"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
