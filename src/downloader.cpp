#include "samloader/downloader.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace samloader {

namespace {

std::runtime_error openssl_error(const std::string& context) {
    std::array<char, 256> buffer{};
    const unsigned long code = ERR_get_error();
    if (code == 0UL) {
        return std::runtime_error(context + " failed");
    }
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return std::runtime_error(context + " failed: " + std::string(buffer.data()));
}

std::vector<std::uint8_t> decrypt_aes_128_ecb(
    const std::vector<std::uint8_t>& ciphertext,
    const std::vector<std::uint8_t>& key) {
    if (key.size() != 16U) {
        throw std::runtime_error("Decrypt failed: expected 16-byte AES-128 key");
    }
    if ((ciphertext.size() % 16U) != 0U) {
        throw std::runtime_error("Decrypt failed: ciphertext is not 16-byte aligned");
    }

    EVP_CIPHER_CTX* raw_ctx = EVP_CIPHER_CTX_new();
    if (raw_ctx == nullptr) {
        throw std::runtime_error("Decrypt failed: could not allocate OpenSSL context");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw_ctx, EVP_CIPHER_CTX_free);

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
        throw openssl_error("AES-128-ECB decrypt init");
    }
    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
        throw openssl_error("AES-128-ECB disable padding");
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size() + 16U);
    int out_len = 0;
    if (EVP_DecryptUpdate(
            ctx.get(),
            plaintext.data(),
            &out_len,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())) != 1) {
        throw openssl_error("AES-128-ECB decrypt update");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &final_len) != 1) {
        throw openssl_error("AES-128-ECB decrypt final");
    }

    plaintext.resize(static_cast<std::size_t>(out_len + final_len));
    return plaintext;
}

void preallocate_file(const std::filesystem::path& path, const std::uint64_t size) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw std::runtime_error("Cannot create output file: " + path.string());
    }

    if (size == 0U) {
        return;
    }

    file.seekp(static_cast<std::streamoff>(size - 1U));
    const char zero = '\0';
    file.write(&zero, 1);
    if (!file) {
        throw std::runtime_error("Cannot pre-allocate output file: " + path.string());
    }
}

void write_chunk_at(const std::filesystem::path& path, const std::uint64_t offset, const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return;
    }

    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        throw std::runtime_error("Cannot open output file for writing: " + path.string());
    }

    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        throw std::runtime_error("Output offset exceeds stream limits");
    }
    file.seekp(static_cast<std::streamoff>(offset));
    if (!file) {
        throw std::runtime_error("Cannot seek output file for writing");
    }

    file.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    if (!file) {
        throw std::runtime_error("Failed writing decrypted chunk to output file");
    }
}

std::string format_human_bytes(double bytes_value) {
    static constexpr std::array<const char*, 5> units{"B", "KiB", "MiB", "GiB", "TiB"};
    std::size_t unit = 0;
    while (bytes_value >= 1024.0 && unit + 1 < units.size()) {
        bytes_value /= 1024.0;
        ++unit;
    }

    std::ostringstream out;
    if (unit == 0U) {
        out << static_cast<std::uint64_t>(bytes_value) << ' ' << units[unit];
    } else {
        out << std::fixed << std::setprecision(2) << bytes_value << ' ' << units[unit];
    }
    return out.str();
}

std::string format_speed(double bytes_per_second) {
    if (bytes_per_second < 0.0) {
        bytes_per_second = 0.0;
    }
    std::ostringstream out;
    out << format_human_bytes(bytes_per_second) << "/s";
    return out.str();
}

std::string format_elapsed(std::chrono::seconds total_seconds) {
    const auto count = total_seconds.count();
    const auto hours = count / 3600;
    const auto minutes = (count % 3600) / 60;
    const auto seconds = count % 60;
    std::ostringstream out;
    out << std::setfill('0')
        << std::setw(2) << hours << ':'
        << std::setw(2) << minutes << ':'
        << std::setw(2) << seconds;
    return out.str();
}

std::string format_eta(std::uint64_t downloaded, std::uint64_t total, double bytes_per_second) {
    if (bytes_per_second <= 0.0 || downloaded >= total) {
        return "--:--:--";
    }
    const double remaining = static_cast<double>(total - downloaded) / bytes_per_second;
    const auto seconds = std::chrono::seconds(static_cast<long long>(remaining));
    return format_elapsed(seconds);
}

std::string make_progress_bar(const std::uint64_t downloaded, const std::uint64_t total) {
    static constexpr std::size_t kWidth = 40;
    std::size_t filled = 0;
    if (total > 0U) {
        filled = static_cast<std::size_t>((downloaded * kWidth) / total);
        if (filled > kWidth) {
            filled = kWidth;
        }
    }
    std::string bar;
    bar.reserve(kWidth * 3U);
    for (std::size_t i = 0; i < filled; ++i) {
        bar += "\xE2\x96\x88";
    }
    for (std::size_t i = filled; i < kWidth; ++i) {
        bar += "\xE2\x96\x91";
    }
    return bar;
}

bool is_retryable_download_error(const std::string& message) {
    static constexpr std::array<std::string_view, 7> retryable_tokens{
        "Transferred a partial file",
        "Server returned nothing",
        "Operation timed out",
        "Recv failure",
        "connection reset",
        "Empty reply from server",
        "HTTP 5",
    };
    for (const auto& token : retryable_tokens) {
        if (message.find(token) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void remove_pkcs7_padding_if_present(const std::filesystem::path& path) {
    const std::uint64_t size = std::filesystem::file_size(path);
    if (size == 0U) {
        return;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open output file for padding check: " + path.string());
    }

    file.seekg(static_cast<std::streamoff>(size - 1U));
    char last = 0;
    file.read(&last, 1);
    if (!file) {
        throw std::runtime_error("Failed reading output file tail byte for padding");
    }

    const std::uint8_t pad = static_cast<std::uint8_t>(last);
    if (pad >= 1U && pad <= 16U) {
        if (size < pad) {
            throw std::runtime_error("Invalid PKCS7 padding size");
        }
        std::filesystem::resize_file(path, size - pad);
    }
}

} // namespace

void Downloader::download(FusClient& client, const std::string& output_path, const std::uint64_t threads) const {
    if (threads == 0U) {
        throw std::runtime_error("Invalid --threads value: must be greater than zero");
    }

    const BinaryInform& info = client.info();
    if (info.filename.empty()) {
        throw std::runtime_error("Download failed: binary info is not loaded");
    }
    if (info.size == 0U) {
        throw std::runtime_error("Download failed: firmware size is zero");
    }
    if (info.key.size() != 16U) {
        throw std::runtime_error("Download failed: BinaryInform key is not 16 bytes");
    }

    const std::filesystem::path out_path(output_path);
    preallocate_file(out_path, info.size);

    const std::uint64_t chunk_size = (info.size / threads / 16U + 1U) * 16U;
    if (chunk_size == 0U) {
        throw std::runtime_error("Download failed: computed chunk size is zero");
    }

    client.init_download();

    std::atomic<std::uint64_t> downloaded_bytes{0};
    std::atomic<bool> stop_progress{false};
    std::mutex error_mutex;
    std::exception_ptr worker_error;

    const auto started_at = std::chrono::steady_clock::now();
    std::thread progress_thread([&]() {
        std::uint64_t last_downloaded = 0;
        auto last_tick = std::chrono::steady_clock::now();
        while (!stop_progress.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            const auto now = std::chrono::steady_clock::now();
            const std::uint64_t current = downloaded_bytes.load(std::memory_order_relaxed);
            const double seconds = std::chrono::duration<double>(now - last_tick).count();
            const double speed = seconds > 0.0
                ? static_cast<double>(current - last_downloaded) / seconds
                : 0.0;
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - started_at);
            const std::string bar = make_progress_bar(current, info.size);
            const std::string eta = format_eta(current, info.size, speed);
            std::cout << '\r'
                      << '[' << format_elapsed(elapsed) << "] "
                      << '[' << bar << "] "
                      << format_human_bytes(static_cast<double>(current)) << '/'
                      << format_human_bytes(static_cast<double>(info.size)) << ' '
                      << '(' << format_speed(speed) << ") "
                      << '[' << eta << ']'
                      << std::flush;
            last_downloaded = current;
            last_tick = now;
        }
    });

    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(threads));

    for (std::uint64_t i = 0, start = 0; start < info.size; ++i, start = i * chunk_size) {
        const bool is_last_worker = i == threads - 1U;
        const std::optional<std::uint64_t> end = is_last_worker
            ? std::nullopt
            : std::optional<std::uint64_t>(start + chunk_size - 1U);

        workers.emplace_back([&, start, end]() {
            try {
                std::vector<std::uint8_t> pending;
                std::uint64_t write_offset = start;
                std::uint64_t request_start = start;
                const auto on_chunk = [&](const std::uint8_t* data, const std::size_t len) {
                    if (len == 0) {
                        return;
                    }

                    pending.insert(pending.end(), data, data + len);
                    const std::size_t aligned = pending.size() - (pending.size() % 16U);
                    if (aligned == 0U) {
                        return;
                    }

                    std::vector<std::uint8_t> encrypted_block(pending.begin(), pending.begin() + aligned);
                    std::vector<std::uint8_t> decrypted = decrypt_aes_128_ecb(encrypted_block, info.key);
                    write_chunk_at(out_path, write_offset, decrypted);
                    write_offset += static_cast<std::uint64_t>(decrypted.size());
                    downloaded_bytes.fetch_add(
                        static_cast<std::uint64_t>(encrypted_block.size()),
                        std::memory_order_relaxed);
                    pending.erase(pending.begin(), pending.begin() + aligned);
                };

                static constexpr int kMaxAttempts = 5;
                for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
                    try {
                        const long status_code = client.download_file_stream(request_start, end, on_chunk);
                        if (status_code != 200L && status_code != 206L) {
                            throw std::runtime_error(
                                "Range request failed: HTTP " + std::to_string(status_code));
                        }
                        if (!pending.empty()) {
                            throw std::runtime_error("Download stream ended with partial AES block");
                        }
                        break;
                    } catch (const std::exception& ex) {
                        if (attempt == kMaxAttempts || !is_retryable_download_error(ex.what())) {
                            throw;
                        }
                        pending.clear();
                        request_start = write_offset;
                        std::this_thread::sleep_for(std::chrono::milliseconds(250 * attempt));
                    }
                }
            } catch (...) {
                std::lock_guard<std::mutex> lock(error_mutex);
                if (worker_error == nullptr) {
                    worker_error = std::current_exception();
                }
            }
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    stop_progress.store(true, std::memory_order_relaxed);
    if (progress_thread.joinable()) {
        progress_thread.join();
    }

    if (worker_error != nullptr) {
        std::rethrow_exception(worker_error);
    }

    const std::uint64_t total_downloaded = downloaded_bytes.load(std::memory_order_relaxed);
    if (total_downloaded != info.size) {
        throw std::runtime_error(
            "Download incomplete: downloaded " + std::to_string(total_downloaded) +
            " bytes, expected " + std::to_string(info.size));
    }

    remove_pkcs7_padding_if_present(out_path);
    const auto finished = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(finished - started_at);
    const double average_speed = elapsed.count() > 0
        ? static_cast<double>(info.size) / static_cast<double>(elapsed.count())
        : 0.0;
    std::cout << '\r'
              << '[' << format_elapsed(elapsed) << "] "
              << '[' << make_progress_bar(info.size, info.size) << "] "
              << format_human_bytes(static_cast<double>(info.size)) << '/'
              << format_human_bytes(static_cast<double>(info.size)) << " ("
              << format_speed(average_speed) << ") "
              << "[00:00:00]"
              << '\n';
}

} // namespace samloader
