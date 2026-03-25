#pragma once

#include <cstdint>
#include <string>

#include "samloader/fus_client.hpp"

namespace samloader {

class Downloader {
public:
    void download(FusClient& client, const std::string& output_path, std::uint64_t threads) const;
};

} // namespace samloader
