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


TEST(Benchmark_LTCMD5, LTCMD5StdString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-md5");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-md5");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is with padding
        algo->Add(IPSUM_LOREM_TEXT);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCMD5::LTCMD5StdString ");

    auto expected = std::string{"e4c88e4f741434e1f25a12f3e0a9451c"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_LTCMD5, LTCMD5CArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-md5");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-md5");

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

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCMD5::LTCMD5CArray ");

    auto expected = std::string{"f6600c29b8b7b51b104c6536ab9764a4"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
