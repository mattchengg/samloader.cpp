#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace samloader {

enum class CommandType {
    Check,
    Download,
};

struct DeviceIdentifier {
    std::string model;
    std::string region;
};

struct FirmwareMetadata {
    std::string version;
    std::string os_version;
    std::string filename;
    std::uint64_t size_bytes{0};
};

struct BinaryInform {
    std::string version;
    std::string filename;
    std::string path;
    std::uint64_t size{0};
    std::vector<std::uint8_t> key;
};

struct AuthToken {
    std::string value;
};

struct DownloadRequest {
    DeviceIdentifier device;
    std::optional<std::string> manual_version;
};

} // namespace samloader
