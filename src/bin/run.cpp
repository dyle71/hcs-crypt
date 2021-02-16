/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>

#include <headcode/crypt/crypt.hpp>
#include <headcode/logger/logger.hpp>
#include <headcode/mem/mem.hpp>

#include "run.hpp"


/**
 * @brief   Adds the data retrieved by a stream (until eof) to the algorithm instance.
 * @param   algorithm       The algorithm instance.
 * @param   stream          The stream to read from.
 * @param   err             The error info stream.
 * @return  exit code (0 == success).
 */
int Add(std::unique_ptr<headcode::crypt::Algorithm> & algorithm, FILE * stream, std::ostream & err) {

    std::uint64_t total_read = 0;
    unsigned char block_incoming[64 * 1024];
    unsigned char block_outgoing[64 * 1024];

    while (stream && !std::feof(stream)) {

        std::uint64_t read = 0;
        try {
            read = std::fread(block_incoming, 1, sizeof(block_incoming), stream);
        } catch (std::exception & ex) {
            err << "Failed to read data: " << ex.what();
            return 1;
        }

        if (read > 0) {

            std::uint64_t size_outgoing = sizeof(block_outgoing);
            algorithm->Add(block_incoming, read, block_outgoing, size_outgoing);

            // TODO: output block to stderr...

            total_read += read;
        }
    }

    return 0;
}


/**
 * @brief   Finalizes the algorithm.
 * @param   result          This will hold the result.
 * @param   config          The config as requested by the user.
 * @param   algorithm       The algorithm instance.
 * @return  exit code (0 == success).
 */
int Finalize(std::vector<std::byte> & result,
             CryptoClientArguments const &,
             std::unique_ptr<headcode::crypt::Algorithm> & algorithm) {
    // TODO: check on finalize data
    return algorithm->Finalize(result);
}


/**
 * @brief   Initializes the algorithm.
 * @param   config          The config as requested by the user.
 * @param   algorithm       The algorithm instance.
 * @return  exit code (0 == success).
 */
int Initialize(CryptoClientArguments const &, std::unique_ptr<headcode::crypt::Algorithm> & algorithm) {
    // TODO: check on initialize data
    return algorithm->Initialize();
}


/**
 * @brief   Produce the output.
 * @param   config          The config as requested by the user.
 * @param   result          The result generated.
 */
void ProcessOutputBlock(CryptoClientArguments const & config, char const * data, std::uint64_t size) {

    if (config.hex_output_ || config.multiline_output_) {
        auto hex = headcode::mem::MemoryToHex(data, size);
        config.out_ << hex;
    } else {
        config.out_ << data;
    }
}


/**
 * @brief   Produce the output.
 * @param   config          The config as requested by the user.
 * @param   name            The name of stream to read from.
 * @param   result          The result generated.
 */
void ProcessOutput(CryptoClientArguments const & config,
                   std::string const & name,
                   std::vector<std::byte> const & result) {

    if (config.multiline_output_) {
        config.out_ << name;
    }

    // do an 64K output loop -> avoid big mem operations on large result sets
    auto data = reinterpret_cast<char const *>(result.data());
    auto size = result.size();
    while (size > 0) {
        auto block_size = std::min(size, 64ul * 1024ul);
        ProcessOutputBlock(config, data, block_size);
        size -= block_size;
        data += block_size;
    }

    if (config.multiline_output_) {
        config.out_ << std::endl;
    }
}


/**
 * @brief   Processes a single file.
 * @param   config          The config as requested by the user.
 * @param   algorithm       The algorithm instance.
 * @param   name            The name of stream to read from.
 * @param   stream          The stream to read from.
 * @return  exit code (0 == success).
 */
int Process(CryptoClientArguments const & config,
            std::unique_ptr<headcode::crypt::Algorithm> & algorithm,
            std::string const & name,
            FILE * stream) {

    int res = Initialize(config, algorithm);
    if (res != 0) {
        return res;
    }

    res = Add(algorithm, stream, config.err_);
    if (res != 0) {
        return res;
    }

    std::vector<std::byte> result;
    res = Finalize(result, config, algorithm);
    if (res != 0) {
        return res;
    }

    ProcessOutput(config, name, result);

    return res;
}


int Run(CryptoClientArguments const & config) {

    auto algorithm = headcode::crypt::Factory::Create(config.algorithm_);
    if (algorithm == nullptr) {
        headcode::logger::Critical{"headcode.crypt"} << "algorithm to use is NULL.";
        return 1;
    }

    int res = 0;
    if (config.input_files_.empty()) {
        res = Process(config, algorithm, "-", stdin);
    } else {

        for (auto const & file_name : config.input_files_) {

            auto input = std::fopen(file_name.c_str(), "rb");
            if (input == nullptr) {
                config.err_ << "Failed to open file: '" << file_name << "' - "
                          << "Failed to open file: " << std::strerror(errno) << std::endl;
                config.err_ << "Aborted." << std::endl;
                return 1;
            }

            res = Process(config, algorithm, file_name, input);
            fclose(input);

            if (res != 0) {
                break;
            }

            // use a new algorithm instance next time
            algorithm = headcode::crypt::Factory::Create(config.algorithm_);
        }
    }

    return res;
}
