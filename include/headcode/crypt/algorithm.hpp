/*
 * This file is part of the headcode.space crypt.
 *
 * The 'LICENSE.txt' file in the project root holds the software license.
 * Copyright (C) 2020-2021 headcode.space e.U.
 * Oliver Maurhart <info@headcode.space>, https://www.headcode.space
 */

#ifndef HEADCODE_SPACE_CRYPT_ALGORITHM_HPP
#define HEADCODE_SPACE_CRYPT_ALGORITHM_HPP

#include <atomic>
#include <cstddef>
#include <map>
#include <string>
#include <vector>
#include <utility>

#include "family.hpp"
#include "padding.hpp"


namespace headcode::crypt {


/**
 * @brief   The Algorithm class is the abstract class for any crypto-algorithm. This is it.
 *
 * Hashes, encryptor and decrypter are all algorithms in this sense:
 * - an algorithm instance is created. This may or may not use an initial key.
 * - data is (repeatedly) added to the algorithm instance, which changes its inner state.
 * - at last the algorithm instance is finalized, again sometimes with a final key and sometimes not.
 *
 * If an initial and/or a final key is used depends on the algorithm itself and can be queried by
 * inspecting the Algorithm::Description.
 *
 * This is a very broad definition and probably not only crypto algorithm fit this approach, since
 * the initial and final keys themselves are basically just memory BLOBs holding anything an
 * algorithm can interpret as initial (or final) data to process.
 *
 * There is one single limitation: an algorithm may be initialized and finalized only once whereas data
 * can be applied in between multiple times.
 */
class Algorithm {

public:
    /**
     * @brief   This holds the algorithm description.
     *
     * Each algorithm has a unqiue name and is associated with a family of algorithms.
     *
     * Each algorithm operates on input data and produce output data. Some algorithm expect
     * the input in specific block sizes. In such cases the value of block_size_incoming
     * will hold a value != 0. If the algorithm produces data in blocks, then the value
     * block_size_outgoing will be set accordingly. If the value is 0 for any or both of
     * these variables, then the value is "unspecified", meaning any arbitrary block size
     * value, including 0.
     *
     * If the algorithm has a defined input block size (not 0), then
     * - the algorithm operates on input data of this size.
     * - the algorithm will most likely pad the input chunks to a multiple of this block size.
     * - the algorithm will most likely produce output with the very same block size each turn.
     *
     * The output block size is different to the result size. The result size constitutes to
     * the final value of an algorithm, e.g. the size of the message digest of hash algorithms.
     *
     * The "Hello World!" example for a scenario with AES 256 CBC is:
     * @code
     *      #include <cstddef>
     *      #include <iostream>
     *      #include <vector>
     *
     *      #include <headcode/mem/mem.hpp>
     *      #include <headcode/crypt/crypt.hpp>
     *
     *      int main(int argc, char ** argv) {
     *
     *          auto key = headcode::mem::StringToMemory("This is my secret key.");
     *          auto iv = headcode::mem::StringToMemory("This is an initialization vector.");
     *
     *          // grab an AES 256 CBC Encryptor
     *          auto algorithm = headcode::crypt::Factory::Create("aes-256-cbc encryptor");
     *          algorithm->Initialize({'key', key}, {'iv', iv});
     *
     *          // encrypt some data (note: the input will be padded!)
     *          std::vector<std::byte> cipher;
     *          algorithm->Add("Hello World!", cipher);
     *
     *          // show the cipher
     *          std::cout << headcode::mem::MemoryToHex(cipher) << std::endl;
     *          return 0;
     *      }
     * @endcode
     *
     * To list all available algorithms see the Factory::GetAlgorithmDescriptions method.
     */
    struct Description {
        /**
         * @brief   This structure defines requirements for input data (most likely the key) used.
         *
         * This structure describes the requirement for input data used in the algorithms. Some algorithms need
         * initial key values, some need final key values, some need none, some need both. The `optional_` field
         * defines if the particular key is needed at all and the `size_` field holds the size in bytes of the
         * key needed. **NOTE**: a `size_` field value of 0 with `optional_` set to false, indicates that the data
         * is needed is but the size is not fixed.
         *
         * The data in here is _most likely_ a key. But may also hold an input vector (IV) or any other
         * data which is needed for a particular algorithm instance.
         */
        struct ArgumentDefinition {

            std::uint64_t size_;                      //!< @brief Defines the required size of the data.
            PaddingStrategy padding_strategy_;        //!< @brief The preferred padding strategy.
            std::string description_;                 //!< @brief A description of this input data.
            bool optional_ = false;        //!< @brief If true, this is an optional and not mandatory data element.
        };

        std::string name_;                     //!< @brief The name of this algorithm.
        Family family_;                        //!< @brief The family of the algorithm.
        std::string description_short_;        //!< @brief A human readable short description of the algorithm.
        std::string description_long_;         //!< @brief A human readable long description of the algorithm.
        std::string provider_;                 //!< @brief Names the provider of the algorithm.

        std::uint64_t block_size_incoming_;             //!< @brief Size of each input block in bytes.
        std::uint64_t block_size_outgoing_;             //!< @brief Size of each output block in bytes.
        PaddingStrategy block_padding_strategy_;        //!< @brief The preferred padding strategy for blocks.
        std::uint64_t result_size_;                     //!< @brief Size of the final result in bytes.

        /**
         * @brief   The needed initialization arguments, identified by name.
         * Hashes most likely do not have any initial arguments. Symmetric ciphers usually
         * need some 'key' and/or 'iv' argument with some defined size.
         */
        std::map<std::string, ArgumentDefinition> initialization_argument_;

        /**
         * @brief   The needed finalization arguments, identified by name.
         * Some algorithms may need a argument for the final computation.
         */
        std::map<std::string, ArgumentDefinition> finalization_argument_;
    };

private:
    std::atomic<bool> finalized_ = false;          //!< @brief Finalized flag (to atomic_flag for test() in C++20)
    std::atomic<bool> initialized_ = false;        //!< @brief Initialized flag (to atomic_flag for test() in C++20)

    /**
     * @brief   Padding strategy applied to blocks at the Add(...) methods.
     */
    PaddingStrategy block_padding_strategy_ = PaddingStrategy::PADDING_PKCS_5_7;

public:
    /**
     * @brief   Constructor.
     * @param   block_padding_strategy      The padding stragegy used for blocks at the Add(...) method.
     */
    explicit Algorithm(PaddingStrategy block_padding_strategy = PaddingStrategy::PADDING_PKCS_5_7)
            : block_padding_strategy_{block_padding_strategy} {
    }

    /**
     * @brief   Copy Constructor.
     */
    Algorithm(Algorithm const &) = delete;

    /**
     * @brief   Move Constructor.
     */
    Algorithm(Algorithm &&) = delete;

    /**
     * @brief   Destructor.
     */
    virtual ~Algorithm() = default;

    /**
     * @brief   Assignment.
     * @return  this.
     */
    Algorithm & operator=(Algorithm const &) = delete;

    /**
     * @brief   Move Assignment.
     * @return  this.
     */
    Algorithm & operator=(Algorithm &&) = delete;

    /**
     * @brief   Adds text to the algorithm
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok, -1 is most likely an error
     * with this . Any other value has to
     * be examined in the context of the algorithm.
     *
     * This variant drops any outgoing blocks the algorithm would produce.
     *
     * If the block_size_incoming_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the input (text) is a multiple of this incoming block size.
     *
     * Padding will be applied as necessary. Padding is expensive though.
     * Check the algorithm's description (call to GetDescription()) about the
     * the incoming block size (block_size_incoming_) and prepare your input
     * data accordingly to avoid costly operations.
     *
     * @param   text                the text to add.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Add(std::string const & text);

    /**
     * @brief   Adds text to the algorithm
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * If the block_size_incoming_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the input (text) is a multiple of this incoming block size.
     *
     * If the block_size_outgoing_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the output (block_outgoing) is a multiple of this outgoing block size.
     *
     * Padding will be applied as necessary. Padding is expensive though.
     * Check the algorithm's description (call to GetDescription()) about the
     * the incoming block size (block_size_incoming_) and prepare your input
     * data accordingly to avoid costly operations.
     *
     * @param   text                the text to add.
     * @param   block_outgoing      the outgoing data block.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Add(std::string const & text, std::vector<std::byte> & block_outgoing);

    /**
     * @brief   Adds data to the algorithm
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * This variant drops any outgoing blocks the algorithm would produce.
     *
     * If the block_size_incoming_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the input (block_incoming) is a multiple of this incoming block size.
     *
     * Padding will be applied as necessary. Padding is expensive though.
     * Check the algorithm's description (call to GetDescription()) about the
     * the incoming block size (block_size_incoming_) and prepare your input
     * data accordingly to avoid costly operations.
     *
     * @param   block_incoming      incoming data block.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Add(std::vector<std::byte> const & block_incoming);

    /**
     * @brief   Adds data to the algorithm
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * If the block_size_incoming_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the input (block_incoming) is a multiple of this incoming block size.
     *
     * If the block_size_outgoing_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the output (block_outgoing) is a multiple of this outgoing block size.
     *
     * Padding will be applied as necessary. Padding is expensive though.
     * Check the algorithm's description (call to GetDescription()) about the
     * the incoming block size (block_size_incoming_) and prepare your input
     * data accordingly to avoid costly operations.
     *
     * @param   block_incoming      incoming data block.
     * @param   block_outgoing      the outgoing data block.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Add(std::vector<std::byte> const & block_incoming, std::vector<std::byte> & block_outgoing);

    /**
     * @brief   Adds data to the algorithm
     *
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * If the block_size_incoming_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the input (block_incoming) is a multiple of this incoming block size.
     *
     * If the block_size_outgoing_ value in the algorithm's description is set
     * to a non-zero value, then it is highly recommended that the length of
     * the output (block_outgoing) is a multiple of this outgoing block size.
     *
     * The data will **not be** padded and will given to the algorithm instance as-is.
     * This method expects the data in the proper format and size suitable for the
     * algorithm. BEWARE: if you do not know how, use the other more convenient
     * Add(...) methods. They do have a more elaborated input checking.
     *
     * @param   block_incoming      incoming data block.
     * @param   size_incoming       size of the incoming data block.
     * @param   block_outgoing      outgoing data block.
     * @param   size_outgoing       size of the outgoing data block (will be adjusted).
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Add(unsigned char const * block_incoming,
            std::uint64_t size_incoming,
            unsigned char * block_outgoing,
            std::uint64_t & size_outgoing);

    /**
     * @brief   Returns the padding strategy used for blocks at the Add(...) method.
     * @return  The padding strategy used for in/out blocks.
     */
    PaddingStrategy GetBlockPaddingStrategy() const {
        return block_padding_strategy_;
    }

    /**
     * @brief   Finalizes this object instance.
     *
     * The concrete implementation of the algorithm may report any error value.
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * You may Finalize the object multiple times.
     *
     * Check the algorithms details/description of what constitutes a good finalization data.
     * Finalization data will be padded (though as this is expensive this should be avoided).
     * Please ensure proper size of finalization data according to algorithm description.
     *
     * @param   result                  the result of the algorithm.
     * @param   finalization_data       the final data (== final key) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Finalize(std::vector<std::byte> & result,
                 std::map<std::string, std::vector<std::byte>> const & finalization_data = {});

    /**
     * @brief   Finalizes this object instance.
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * The object **WILL NOT** be finalized twice.
     *
     * Check the algorithms details/description of what constitutes a good finalization data.
     * Finalization data will be padded (though as this is expensive this should be avoided).
     * Please ensure proper size of finalization data according to algorithm description.
     *
     * @param   result                  the result of the algorithm.
     * @param   finalization_data       the final data (== final key) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Finalize(std::vector<std::byte> & result,
                 std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & finalization_data);

    /**
     * @brief   Finalizes this object instance.
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * The object **WILL NOT** be finalized twice.
     *
     * Check the algorithms details/description of what constitutes a good finalization data.
     *
     * BEWARE: There will be NO padding of the finalization data here, but this data will
     * be passed on as-is to the algorithm, meaning result memory has to be at a proper size.
     * If in doubt, use one of the other Finalize(...) using byte vectors methods.
     *
     * @param   result                  the result of the algorithm.
     * @param   result_size             size of the result for finalization.
     * @param   finalization_data       the final data (== final key) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Finalize(unsigned char * result,
                 std::uint64_t result_size,
                 std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & finalization_data);

    /**
     * @brief   Gets the algorithm description.
     * @return  A structure describing the algorithm.
     * */
    Description const & GetDescription() const;

    /**
     * @brief   Initialize this object instance.
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * The object **WILL NOT** be initialized twice.
     *
     * Check the algorithms details/description of what constitutes a good init data.
     *
     * @param   initialization_data     the initial data (== initial key, IV, ...) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Initialize(std::map<std::string, std::vector<std::byte>> const & initialization_data = {});

    /**
     * @brief   Initialize this object instance.
     *
     * The concrete implementation of the algorithm may report any error value.
     *
     * As a rule of thumb: returning 0 is always ok. Any other value has to
     * be examined in the context of the algorithm.
     *
     * The object **WILL NOT** be initialized twice.
     *
     * Check the algorithms details/description of what constitutes a good init data.
     *
     * BEWARE: the given data will be handed out to the algorithm as-is, i.e. the memory
     * pointers as well as the size *must* be sufficient. If in doubt, use the other
     * Initialize(...) methods using byte vectors.
     *
     * @param   initialization_data     the initial data (== initial key, IV, ...) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    int Initialize(std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data);

    /**
     * @brief   Checks if this algorithm instance has been finalized.
     * @return  true, if we finalized this algorithm object.
     */
    bool IsFinalized() const {
        return finalized_;
    }

    /**
     * @brief   Checks if this algorithm instance has been initialized.
     * @return  true, if we init this algorithm object.
     */
    bool IsInitialized() const {
        return initialized_;
    }

    /**
     * @brief   Sets a new padding strategy used for blocks at the Add(...) method.
     * This changes the padding strategy applied to blocks at the Add(...) method.
     * @param   block_padding_strategy      the new block padding strategy.
     */
    void SetBlockPaddingStrategy(PaddingStrategy block_padding_strategy) {
        block_padding_strategy_ = block_padding_strategy;
    }

private:
    /**
     * @brief   Adds data to the algorithm
     * @param   block_incoming      incoming data block to add.
     * @param   size_incoming       size of the incoming data to add.
     * @param   block_outgoing      outgoing data block.
     * @param   size_outgoing       size of the outgoing data block (will be adjusted).
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    virtual int Add_(unsigned char const * block_incoming,
                     std::uint64_t size_incoming,
                     unsigned char * block_outgoing,
                     std::uint64_t & size_outgoing) = 0;

    /**
     * @brief   Finalizes this object instance.
     * @param   result                  the result of the algorithm.
     * @param   result_size             size of the result for finalization.
     * @param   finalization_data       the final data (== final key) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    virtual int Finalize_(
            unsigned char * result,
            std::uint64_t result_size,
            std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & finalization_data) = 0;

    /**
     * @brief   Gets the algorithm description.
     * @return  A string describing the algorithm.
     * */
    virtual Description const & GetDescription_() const = 0;

    /**
     * @brief   Initialize this object instance.
     * @param   initialization_data     the initial data (== initial key, IV, ...) to use, if any.
     * @return  Error enum value if negativ (0 == ok), else something in the context of the algorithm provider.
     */
    virtual int Initialize_(
            std::map<std::string, std::tuple<unsigned char const *, std::uint64_t>> const & initialization_data) = 0;
};


}


#endif
