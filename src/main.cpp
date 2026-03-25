#include "samloader/downloader.hpp"
#include "samloader/fus_client.hpp"

#include <cstdlib>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

enum class Command {
    Check,
    Download,
};

struct ParsedArgs {
    std::string model;
    std::string region;
    std::uint64_t threads{8};
    Command command{Command::Check};
    std::optional<std::string> out_dir;
    std::optional<std::string> out_file;
};

bool is_command(const std::string& token) {
    return token == "check" || token == "download";
}

std::uint64_t parse_threads(const std::string& value) {
    std::size_t consumed = 0;
    unsigned long long parsed = 0;
    try {
        parsed = std::stoull(value, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid --threads value: " + value);
    }
    if (consumed != value.size() || parsed == 0ULL) {
        throw std::runtime_error("Invalid --threads value: " + value);
    }
    return static_cast<std::uint64_t>(parsed);
}

std::string strip_enc4_suffix(const std::string& filename) {
    constexpr const char* kSuffix = ".enc4";
    constexpr std::size_t kSuffixLen = 5;
    if (filename.size() >= kSuffixLen &&
        filename.compare(filename.size() - kSuffixLen, kSuffixLen, kSuffix) == 0) {
        return filename.substr(0, filename.size() - kSuffixLen);
    }
    return filename;
}

void print_usage(const char* program_name, std::ostream& out) {
    out << "Usage: " << program_name << " [OPTIONS] --model <MODEL> --region <REGION> <COMMAND>\n\n"
        << "Commands:\n"
        << "  download  Download the latest firmware\n"
        << "  check     Check the latest version\n\n"
        << "Options:\n"
        << "  -m, --model <MODEL>      The model name (e.g. SM-S931U1)\n"
        << "  -r, --region <REGION>    Region CSC code (e.g. XAA)\n"
        << "  -j, --threads <THREADS>  Number of parallel connections [default: 8]\n"
        << "  -h, --help               Print help\n"
        << "  download options:\n"
        << "      -O, --out_dir <DIR>   Output directory\n"
        << "      -o, --out_file <FILE> Output file path\n";
}

ParsedArgs parse_args(int argc, char** argv) {
    if (argc < 2) {
        throw std::runtime_error("Missing arguments");
    }

    ParsedArgs args;
    std::optional<Command> command;

    std::vector<std::string> tokens;
    tokens.reserve(static_cast<std::size_t>(argc - 1));
    for (int i = 1; i < argc; ++i) {
        tokens.emplace_back(argv[i]);
    }

    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];

        if (token == "-h" || token == "--help") {
            print_usage(argv[0], std::cout);
            std::exit(0);
        }

        if (!command.has_value() && is_command(token)) {
            command = (token == "check") ? Command::Check : Command::Download;
            continue;
        }

        auto next_value = [&]() -> std::string {
            if (i + 1 >= tokens.size()) {
                throw std::runtime_error("Missing value for option: " + token);
            }
            ++i;
            return tokens[i];
        };

        if (token == "-m" || token == "--model") {
            args.model = next_value();
            continue;
        }
        if (token == "-r" || token == "--region") {
            args.region = next_value();
            continue;
        }
        if (token == "-j" || token == "--threads") {
            args.threads = parse_threads(next_value());
            continue;
        }
        if (token == "-O" || token == "--out_dir") {
            if (command.has_value() && *command != Command::Download) {
                throw std::runtime_error("--out_dir is only valid for download command");
            }
            args.out_dir = next_value();
            continue;
        }
        if (token == "-o" || token == "--out_file") {
            if (command.has_value() && *command != Command::Download) {
                throw std::runtime_error("--out_file is only valid for download command");
            }
            args.out_file = next_value();
            continue;
        }

        if (is_command(token) && command.has_value()) {
            throw std::runtime_error("Multiple commands provided");
        }
        throw std::runtime_error("Unknown argument: " + token);
    }

    if (!command.has_value()) {
        throw std::runtime_error("Missing command: expected check or download");
    }
    if (args.model.empty()) {
        throw std::runtime_error("Missing required option: --model");
    }
    if (args.region.empty()) {
        throw std::runtime_error("Missing required option: --region");
    }
    if (*command == Command::Check && (args.out_dir.has_value() || args.out_file.has_value())) {
        throw std::runtime_error("--out_dir/--out_file are only valid for download command");
    }

    args.command = *command;
    return args;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const ParsedArgs args = parse_args(argc, argv);
        samloader::FusClient client;
        client.fetch_binary_info(args.model, args.region);

        if (args.command == Command::Check) {
            std::cout << client.info().version << '\n';
            return 0;
        }

        const auto& info = client.info();
        const std::string default_name = strip_enc4_suffix(info.filename);
        std::string final_out;
        if (args.out_file.has_value()) {
            final_out = *args.out_file;
        } else if (args.out_dir.has_value()) {
            final_out = *args.out_dir;
            if (!final_out.empty() && final_out.back() != '/') {
                final_out.push_back('/');
            }
            final_out += default_name;
        } else {
            final_out = default_name;
        }

        std::cout << "Firmware Version: " << info.version << '\n';
        std::cout << "Downloading " << info.filename << " to " << final_out << '\n';

        samloader::Downloader downloader;
        downloader.download(client, final_out, args.threads);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        print_usage(argv[0], std::cerr);
        return 1;
    }
}
