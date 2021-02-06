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


TEST(Benchmark_LTCAES192ECB, LTCAES192ECBString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-aes-192-ecb-encryptor");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-aes-192-ecb-encryptor");

    auto key = headcode::mem::StringToMemory(
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious");

    auto key_enc = key;
    key_enc.resize(algo->GetDescription().initialization_argument_.at("key").size_);
    ASSERT_EQ(algo->Initialize({{"key", key_enc}}), 0);

    std::vector<std::byte> cipher;
    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is with padding but reusing the ciper everytime.
        ASSERT_EQ(algo->Add(kIpsumLoremText, cipher), 0);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * kIpsumLoremText.size()};

    std::cout << StreamPerformanceIndicators(throughput,
                                             "Benchmark Benchmark_LTCAES192ECB::LTCAES192ECBString ");
}


TEST(Benchmark_LTCAES192ECB, LTCAES192ECBCArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-aes-192-ecb-encryptor");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-aes-192-ecb-encryptor");

    auto key = headcode::mem::StringToMemory(
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious"
            "supercalifragilisticexpialidocious");

    auto key_enc = key;
    key_enc.resize(algo->GetDescription().initialization_argument_.at("key").size_);
    ASSERT_EQ(algo->Initialize({{"key", key_enc}}), 0);

    auto block_incoming = kIpsumLoremText.c_str();
    auto current_size = std::strlen(block_incoming);
    auto total_size = current_size;

    ASSERT_GT(current_size, 0ul);
    auto block_size = algo->GetDescription().block_size_incoming_;
    ASSERT_GT(block_size, 0ul);
    if ((current_size % block_size) != 0) {
        total_size = current_size + (block_size - (current_size % block_size));
    }
    auto block = new unsigned char[total_size];
    std::memcpy(block, block_incoming, current_size);
    headcode::crypt::Pad(block,
                         total_size,
                         current_size,
                         algo->GetDescription().block_size_incoming_,
                         algo->GetDescription().block_padding_strategy_);

    auto cipher = new unsigned char[total_size];
    std::uint64_t cipher_size;

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is without padding
        ASSERT_EQ(algo->Add(block, total_size, cipher, cipher_size), 0);
    }

    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * total_size};
    delete [] cipher;
    delete [] block;

    std::cout << StreamPerformanceIndicators(throughput,
                                             "Benchmark Benchmark_LTCAES192ECB::LTCAES192ECBCArray ");
}
