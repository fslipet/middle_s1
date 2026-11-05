#include "../CoutToString.h"
#include "../include/cmd_options.h"
#include <gtest/gtest.h>

#include <vector>

struct DataOption {
    inline static constexpr std::string input_{"input.txt"};
    inline static constexpr std::string output_{"output.en"};
    inline static constexpr std::string password_{"12345"};
};

TEST(ProgramOptions, Empty) {
    CryptoGuard::ProgramOptions options;
    int argc = 1;
    std::vector<char *> argv{'\\'};
    CoutToString text_result;
    ASSERT_EQ(options.Parse(argc, argv.data()), false);
    ASSERT_EQ(text_result.GetString(), "missing file operand. See \'--help\' for more information.\n");
}

TEST(ProgramOptions, Help) {
    CryptoGuard::ProgramOptions options;
    int argc = 2;
    std::vector<const char *> argv{'\\', "--help"};
    CoutToString text_result;
    ASSERT_EQ(options.Parse(argc, const_cast<char **>(argv.data())), false);
    std::string result =
        "Allowed options:\n  -h [ --help ]               Show help\n  --command arg               \xD1\x81ommand: "
        "encrypt, decrypt, checksum\n  -i [ --input ] input file   set the path to the input file\n  -o [ --output ] "
        "output file set the path to the output file\n  -p [ --password ] password  set password\n";
    ASSERT_EQ(text_result.GetString(), result);
}

TEST(ProgramOptions, Checksum) {
    CryptoGuard::ProgramOptions options;
    using DO = DataOption;
    int argc = 5;
    std::vector<const char *> argv{"\\", "-i", DO::input_.data(), "--command", "checksum"};
    ASSERT_EQ(options.Parse(argc, const_cast<char **>(argv.data())), true);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    ASSERT_EQ(options.GetInputFile(), DO::input_);
}

TEST(ProgramOptions, Encrypt) {
    CryptoGuard::ProgramOptions options;
    using DO = DataOption;
    int argc = 9;
    std::vector<const char *> argv{
        "\\", "-i", DO::input_.data(), "--command", "encrypt", "-o", DO::output_.data(), "-p", DO::password_.data()};
    CoutToString text_result;
    ASSERT_EQ(options.Parse(argc, const_cast<char **>(argv.data())), true);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    ASSERT_EQ(options.GetInputFile(), DO::input_);
    ASSERT_EQ(options.GetOutputFile(), DO::output_);
    ASSERT_EQ(options.GetPassword(), DO::password_);
}

TEST(ProgramOptions, EncryptLong) {
    CryptoGuard::ProgramOptions options;
    using DO = DataOption;
    int argc = 9;
    std::vector<const char *> argv{
        "\\", "--command", "encrypt", "--input", DO::input_.data(), "--output", DO::output_.data(), "--password", DO::password_.data()};
    CoutToString text_result;
    ASSERT_EQ(options.Parse(argc, const_cast<char **>(argv.data())), true);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    ASSERT_EQ(options.GetInputFile(), DO::input_);
    ASSERT_EQ(options.GetOutputFile(), DO::output_);
    ASSERT_EQ(options.GetPassword(), DO::password_);
}

TEST(ProgramOptions, Decrypt) {
    CryptoGuard::ProgramOptions options;
    using DO = DataOption;
    int argc = 9;
    std::vector<const char *> argv{
        "\\", "-i", DO::input_.data(), "--command", "decrypt", "-o", DO::output_.data(), "-p", DO::password_.data()};
    CoutToString text_result;
    ASSERT_EQ(options.Parse(argc, const_cast<char **>(argv.data())), true);
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    ASSERT_EQ(options.GetInputFile(), DO::input_);
    ASSERT_EQ(options.GetOutputFile(), DO::output_);
    ASSERT_EQ(options.GetPassword(), DO::password_);
}

TEST(ProgramOptions, ThrowsWrongCommand) {
    CryptoGuard::ProgramOptions options;
    int argc = 2;
    std::vector<const char *> argv{'\\', "help"};
    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv.data())), std::runtime_error);
}