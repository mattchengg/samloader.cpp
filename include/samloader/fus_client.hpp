#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "samloader/types.hpp"

namespace samloader {

struct DownloadResponse {
    long status_code{0};
    std::vector<std::uint8_t> bytes;
};

class FusClient {
public:
    using DownloadChunkCallback = std::function<void(const std::uint8_t* data, std::size_t len)>;

    FusClient();

    const BinaryInform& fetch_binary_info(const std::string& model, const std::string& region);
    void init_download();
    DownloadResponse download_file(std::optional<std::uint64_t> start, std::optional<std::uint64_t> end) const;
    long download_file_stream(
        std::optional<std::uint64_t> start,
        std::optional<std::uint64_t> end,
        const DownloadChunkCallback& on_chunk) const;

    const BinaryInform& info() const noexcept;
    std::string create_download_url() const;

    FirmwareMetadata check_firmware(const DownloadRequest& request);
    std::string create_download_url(const FirmwareMetadata& firmware) const;

private:
    struct HttpResponse;

    HttpResponse make_post_request(
        const std::string& path,
        const std::string& body,
        std::optional<long> timeout_seconds = std::nullopt);
    std::vector<std::string> make_headers(bool include_cookie = true) const;
    void apply_response_state(const HttpResponse& response);

    std::string auth_;
    std::string sessid_;
    std::string nonce_;
    std::string encnonce_;
    BinaryInform info_;
};

} // namespace samloader
