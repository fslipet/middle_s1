#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <cctype>
#include <fstream>
#include <ios>
#include <iostream>
#include <print>
#include <ranges>
#include <stdexcept>

int main(int argc, char *argv[]) {
    using namespace CryptoGuard;
    ProgramOptions options;
    try {
        if (!options.Parse(argc, argv)) {
            return 0;
        }

        CryptoGuardCtx crypto_ctx;
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        std::fstream i_file(options.GetInputFile(), std::ios_base::in);

        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream o_file(options.GetOutputFile(), std::ios_base::out);
            crypto_ctx.EncryptFile(i_file, o_file, options.GetPassword());
            std::print("File encoded successfully\n");
        } break;

        case COMMAND_TYPE::DECRYPT: {
            std::fstream o_file(options.GetOutputFile(), std::ios_base::out);
            crypto_ctx.DecryptFile(i_file, o_file, options.GetPassword());
            std::print("File decoded successfully\n");
        } break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum:  {}\n", crypto_ctx.CalculateChecksum(i_file) |
                                              std::views::transform([](unsigned char c) { return std::toupper(c); }) |
                                              std::ranges::to<std::string>());
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }
    } catch (boost::program_options::error &e) {
        std::cerr << e.what() << '\n';
        std::print(std::cerr, "Unknown command. See --help\n");
        return 1;
    } catch (const std::ios_base::failure &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
    } catch (std::runtime_error &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}