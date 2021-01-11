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


TEST(BenchmarkLTCSHA512, LTCSHA512StdString1000) {

    auto loop_count = 1'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha512");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        algo->Add(IPSUM_LOREM_TEXT);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkLTCSHA512::LTCSHA512StdString1000 ");

    auto expected = std::string{
            "86cb163e248030e9a69b58f528427698"
            "2fcc1d0400039da7485bee8ec76fd55b"
            "068a2d53875ac7020dfc0960b05beac6"
            "131cd8fafb4beb73a9608ce044fb432e"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(BenchmarkLTCSHA512, LTCSHA512CArray1000) {

    auto loop_count = 1'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha512");

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

    std::cout << StreamPerformanceIndicators(throughput, "BenchmarkLTCSHA512::LTCSHA512CArray1000 ");

    auto expected = std::string{
            "86cb163e248030e9a69b58f528427698"
            "2fcc1d0400039da7485bee8ec76fd55b"
            "068a2d53875ac7020dfc0960b05beac6"
            "131cd8fafb4beb73a9608ce044fb432e"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
