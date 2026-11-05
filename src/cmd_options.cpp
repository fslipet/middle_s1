#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {
namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    desc_.add_options()("help,h", "Show help")("command", po::value<std::string>(),
                                               "сommand: encrypt, decrypt, checksum")(
        "input,i", po::value(&inputFile_)->value_name("input file"), "set the path to the input file")(
        "output,o", po::value(&outputFile_)->value_name("output file"),
        "set the path to the output file")("password,p", po::value(&password_)->value_name("password"), "set password");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    if (argc == 1) {
        std::cout << "missing file operand. See \'--help\' for more information.\n";
        return false;
    }

    // variables_map хранит значения опций после разбора
    po::variables_map vm;
    auto parsed = po::parse_command_line(argc, argv, desc_);
    po::store(parsed, vm);
    po::notify(vm);

    if (vm.contains("help")) {
        // Если был указан параметр --help, то выводим справку
        std::cout << desc_;
        return false;
    }

    // Проверяем наличие опций
    if (!vm.contains("command")) {
        throw std::runtime_error("Error not found \'--command\'.\nSee \'--help\' for more information.\n");
    }

    std::string sub_cmd = vm["command"].as<std::string>();
    if (auto it = commandMapping_.find(std::move(sub_cmd)); it != commandMapping_.end()) {
        command_ = it->second;
    } else {
        throw std::runtime_error("Unknown command. See \'--help\' for more information.\n");
    }

    if (!vm.contains("input") || inputFile_.empty()) {
        throw std::runtime_error("Input file have not been specified\nSee \'--help\' for more information.\n");
    }

    if (command_ != COMMAND_TYPE::CHECKSUM && (!vm.contains("output") || outputFile_.empty())) {
        throw std::runtime_error("Output file have not been specified\nSee \'--help\' for more information.\n");
    }

    return true;
}

}  // namespace CryptoGuard
