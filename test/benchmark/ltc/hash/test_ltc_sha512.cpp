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


TEST(Benchmark_LTCSHA512, LTCSHA512StdString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha512");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is with padding
        algo->Add(kIpsumLoremText);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * kIpsumLoremText.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCSHA512::LTCSHA512StdString ");

    auto expected = std::string{
            "2debfe2de82fea9c4186950a632533e5"
            "64167ae88b81d8c3217b508a1c5169dc"
            "e43aeaa226843a80f5bf2e6d95eee73b"
            "fb64d1f5deb75003ceca40610bb4de94"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_LTCSHA512, LTCSHA512CArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-sha512");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha512");

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

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCSHA512::LTCSHA512CArray ");

    auto expected = std::string{
            "bd6ee03900f6b3f946c54a810bfe9fe5"
            "c269859d87d66149a9936d08a74cd7d1"
            "cc569914480870fbfa8e23937193fa1f"
            "4680505c6484a42c55d96a1053688529"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
