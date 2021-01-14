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


TEST(Benchmark_LTCSHA1, LTCSHA1StdString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-sha1");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha1");

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is with padding
        algo->Add(IPSUM_LOREM_TEXT);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCSHA1::LTCSHA1StdString ");

    auto expected = std::string{"adef2f9c47de610fb523df65a81dc2a96f57a7ec"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}


TEST(Benchmark_LTCSHA1, LTCSHA1CArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-sha1");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-sha1");

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

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark LTCSHA1::LTCSHA1CArray ");

    auto expected = std::string{"cae61d20a6352a4271f11417b041725768159a2a"};
    EXPECT_STREQ(headcode::mem::MemoryToHex(result).c_str(), expected.c_str());
}
