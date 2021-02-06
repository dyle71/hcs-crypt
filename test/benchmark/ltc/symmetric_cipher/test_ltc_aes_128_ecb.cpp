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


TEST(Benchmark_LTCAES128ECB, LTCAES128ECBString) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-aes-128-ecb-encryptor");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-aes-128-ecb-encryptor");

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
        ASSERT_EQ(algo->Add(IPSUM_LOREM_TEXT, cipher), 0);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * IPSUM_LOREM_TEXT.size()};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark Benchmark_LTCAES128ECB::LTCAES128ECBString ");
}


TEST(Benchmark_LTCAES128ECB, LTCAES128ECBCArray) {

    auto loop_count = 100'000u;

    auto algo = headcode::crypt::Factory::Create("ltc-aes-128-ecb-encryptor");
    ASSERT_NE(algo.get(), nullptr);
    EXPECT_STREQ(algo->GetDescription().name_.c_str(), "ltc-aes-128-ecb-encryptor");

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

    auto block_incoming = IPSUM_LOREM_TEXT.c_str();
    auto size_incoming = std::strlen(block_incoming);

    // makes rounds up the cipher size with a multiple of 128 bit
    std::vector<std::byte> cipher;
    auto cipher_size = size_incoming >> 7;
    cipher_size++;
    cipher_size <<= 7;
    cipher.resize(cipher_size);

    auto time_start = std::chrono::high_resolution_clock::now();
    for (std::uint64_t i = 0; i < loop_count; ++i) {
        // this is without padding
        ASSERT_EQ(algo->Add(reinterpret_cast<unsigned char const *>(block_incoming),
                            size_incoming,
                            reinterpret_cast<unsigned char *>(cipher.data()),
                            cipher_size),
                  0);
    }
    std::vector<std::byte> result;
    algo->Finalize(result);
    headcode::benchmark::Throughput throughput{headcode::benchmark::GetElapsedMicroSeconds(time_start),
                                               loop_count * size_incoming};

    std::cout << StreamPerformanceIndicators(throughput, "Benchmark Benchmark_LTCAES128ECB::LTCAES128ECBCArray ");
}
