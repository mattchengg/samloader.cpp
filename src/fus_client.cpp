#include "samloader/fus_client.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "samloader/auth.hpp"
#include "samloader/xml.hpp"

namespace samloader {

namespace {

constexpr const char* kApiBaseUrl = "https://neofussvr.sslcs.cdngc.net/";
constexpr const char* kDownloadBaseUrl =
    "http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do?file=";
constexpr const char* kUserAgent = "Kies2.0_FUS";

using CurlHandle = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>;
using CurlHeaderList = std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)>;

struct HeaderCapture {
    std::optional<std::string> nonce;
    std::vector<std::string> set_cookie_headers;
};

void ensure_curl_initialized() {
    static const bool initialized = []() {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            throw std::runtime_error("libcurl global initialization failed");
        }
        return true;
    }();
    (void)initialized;
}

std::string trim_copy(std::string value) {
    auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
    value.erase(
        value.begin(),
        std::find_if(value.begin(), value.end(), not_space));
    value.erase(
        std::find_if(value.rbegin(), value.rend(), not_space).base(),
        value.end());
    return value;
}

std::string to_lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

void throw_if_curl_error(const CURLcode code, const std::string& context) {
    if (code != CURLE_OK) {
        throw std::runtime_error(context + ": " + curl_easy_strerror(code));
    }
}

CurlHandle create_curl_handle() {
    CURL* raw = curl_easy_init();
    if (raw == nullptr) {
        throw std::runtime_error("Failed to create libcurl handle");
    }
    return CurlHandle(raw, curl_easy_cleanup);
}

CurlHeaderList build_curl_header_list(const std::vector<std::string>& headers) {
    curl_slist* raw_headers = nullptr;
    for (const auto& header : headers) {
        curl_slist* appended = curl_slist_append(raw_headers, header.c_str());
        if (appended == nullptr) {
            if (raw_headers != nullptr) {
                curl_slist_free_all(raw_headers);
            }
            throw std::runtime_error("Failed to allocate libcurl HTTP headers");
        }
        raw_headers = appended;
    }
    return CurlHeaderList(raw_headers, curl_slist_free_all);
}

void configure_common_options(CURL* handle) {
    throw_if_curl_error(
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L),
        "Failed to configure redirect handling");
    throw_if_curl_error(
        curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, ""),
        "Failed to configure HTTP compression");
}

long get_response_code(CURL* handle, const std::string& context) {
    long status_code = 0;
    throw_if_curl_error(
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status_code),
        context + ": failed to read HTTP status");
    return status_code;
}

size_t append_to_string(char* ptr, size_t size, size_t nmemb, void* userdata) {
    if (ptr == nullptr || userdata == nullptr) {
        return 0;
    }
    const std::size_t bytes = size * nmemb;
    auto* output = static_cast<std::string*>(userdata);
    output->append(ptr, bytes);
    return bytes;
}

size_t append_to_bytes(char* ptr, size_t size, size_t nmemb, void* userdata) {
    if (ptr == nullptr || userdata == nullptr) {
        return 0;
    }
    const std::size_t bytes = size * nmemb;
    auto* output = static_cast<std::vector<std::uint8_t>*>(userdata);
    output->insert(output->end(), ptr, ptr + bytes);
    return bytes;
}

struct StreamContext {
    const FusClient::DownloadChunkCallback* callback{nullptr};
    std::size_t total_bytes{0};
};

size_t stream_to_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    if (ptr == nullptr || userdata == nullptr) {
        return 0;
    }
    const std::size_t bytes = size * nmemb;
    auto* ctx = static_cast<StreamContext*>(userdata);
    if (ctx->callback == nullptr) {
        return 0;
    }
    (*ctx->callback)(reinterpret_cast<const std::uint8_t*>(ptr), bytes);
    ctx->total_bytes += bytes;
    return bytes;
}

size_t capture_headers(char* buffer, size_t size, size_t nitems, void* userdata) {
    if (buffer == nullptr || userdata == nullptr) {
        return 0;
    }
    const std::size_t bytes = size * nitems;
    auto* capture = static_cast<HeaderCapture*>(userdata);

    std::string line(buffer, bytes);
    const auto separator_pos = line.find(':');
    if (separator_pos == std::string::npos) {
        return bytes;
    }

    std::string name = to_lower_ascii(trim_copy(line.substr(0, separator_pos)));
    std::string value = trim_copy(line.substr(separator_pos + 1));
    if (name == "nonce") {
        capture->nonce = value;
    } else if (name == "set-cookie") {
        capture->set_cookie_headers.push_back(value);
    }

    return bytes;
}

std::optional<std::string> extract_jsessionid(const std::string& set_cookie_header) {
    const auto cookie_end = set_cookie_header.find(';');
    const std::string cookie_pair = trim_copy(set_cookie_header.substr(0, cookie_end));
    const auto separator_pos = cookie_pair.find('=');
    if (separator_pos == std::string::npos) {
        return std::nullopt;
    }

    const std::string name = trim_copy(cookie_pair.substr(0, separator_pos));
    if (!name.starts_with("JSESSIONID")) {
        return std::nullopt;
    }

    return trim_copy(cookie_pair.substr(separator_pos + 1));
}

std::string truncate_for_error(std::string text) {
    constexpr std::size_t kMaxErrorBody = 256;
    if (text.size() > kMaxErrorBody) {
        text.resize(kMaxErrorBody);
        text.append("...");
    }
    return text;
}

} // namespace

struct FusClient::HttpResponse {
    long status_code{0};
    std::string body;
    std::optional<std::string> nonce;
    std::vector<std::string> set_cookie_headers;
};

FusClient::FusClient() {
    ensure_curl_initialized();

    const HttpResponse response = make_post_request("NF_DownloadGenerateNonce.do", "");
    if (!response.nonce.has_value() || response.nonce->empty()) {
        throw std::runtime_error("FUS initialization failed: NONCE response header is missing");
    }
}

const BinaryInform& FusClient::fetch_binary_info(const std::string& model, const std::string& region) {
    const std::string request_xml = xml::build_binary_inform_request_xml(model, region);
    const HttpResponse response = make_post_request("NF_DownloadBinaryInform.do", request_xml, 3L);

    auto parsed_info = xml::parse_binary_inform(response.body);
    if (!parsed_info.has_value()) {
        throw std::runtime_error("Info request invalid: failed to parse BinaryInform payload");
    }
    info_ = std::move(*parsed_info);
    return info_;
}

void FusClient::init_download() {
    if (info_.filename.empty()) {
        throw std::runtime_error("Download init failed: binary info is not loaded");
    }
    if (nonce_.empty()) {
        throw std::runtime_error("Download init failed: decrypted nonce is missing");
    }

    const std::string init_xml = xml::build_binary_init_request_xml(info_.filename, nonce_);
    make_post_request("NF_DownloadBinaryInitForMass.do", init_xml);
}

DownloadResponse FusClient::download_file(
    const std::optional<std::uint64_t> start,
    const std::optional<std::uint64_t> end) const {
    const std::string url = create_download_url();
    auto curl = create_curl_handle();
    configure_common_options(curl.get());

    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str()),
        "Failed to configure download URL");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_HTTPGET, 1L),
        "Failed to configure HTTP GET request");

    std::vector<std::string> headers = make_headers(false);
    if (start.has_value() && end.has_value()) {
        headers.emplace_back("Range: bytes=" + std::to_string(*start) + "-" + std::to_string(*end));
    } else if (start.has_value()) {
        headers.emplace_back("Range: bytes=" + std::to_string(*start) + "-");
    } else if (end.has_value()) {
        headers.emplace_back("Range: bytes=0-" + std::to_string(*end));
    }
    auto header_list = build_curl_header_list(headers);
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, header_list.get()),
        "Failed to set download HTTP headers");

    std::vector<std::uint8_t> response_body;
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, append_to_bytes),
        "Failed to configure download write callback");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response_body),
        "Failed to configure download output target");

    throw_if_curl_error(
        curl_easy_perform(curl.get()),
        "Download request failed");

    const long status_code = get_response_code(curl.get(), "Download request");
    if (status_code >= 400) {
        throw std::runtime_error(
            "Download request failed: HTTP " + std::to_string(status_code));
    }

    return DownloadResponse{status_code, std::move(response_body)};
}

long FusClient::download_file_stream(
    const std::optional<std::uint64_t> start,
    const std::optional<std::uint64_t> end,
    const DownloadChunkCallback& on_chunk) const {
    const std::string url = create_download_url();
    auto curl = create_curl_handle();
    configure_common_options(curl.get());

    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str()),
        "Failed to configure download URL");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_HTTPGET, 1L),
        "Failed to configure HTTP GET request");

    std::vector<std::string> headers = make_headers(false);
    if (start.has_value() && end.has_value()) {
        headers.emplace_back("Range: bytes=" + std::to_string(*start) + "-" + std::to_string(*end));
    } else if (start.has_value()) {
        headers.emplace_back("Range: bytes=" + std::to_string(*start) + "-");
    } else if (end.has_value()) {
        headers.emplace_back("Range: bytes=0-" + std::to_string(*end));
    }
    auto header_list = build_curl_header_list(headers);
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, header_list.get()),
        "Failed to set download HTTP headers");

    StreamContext stream_ctx{&on_chunk, 0};
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, stream_to_callback),
        "Failed to configure stream write callback");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &stream_ctx),
        "Failed to configure stream output target");

    throw_if_curl_error(
        curl_easy_perform(curl.get()),
        "Download request failed");

    const long status_code = get_response_code(curl.get(), "Download request");
    if (status_code >= 400) {
        throw std::runtime_error(
            "Download request failed: HTTP " + std::to_string(status_code));
    }

    if (stream_ctx.total_bytes == 0) {
        throw std::runtime_error("Range request returned empty payload");
    }
    return status_code;
}

const BinaryInform& FusClient::info() const noexcept {
    return info_;
}

std::string FusClient::create_download_url() const {
    if (info_.filename.empty()) {
        throw std::runtime_error("Download URL unavailable: binary info is not loaded");
    }
    return std::string(kDownloadBaseUrl) + info_.path + info_.filename;
}

FirmwareMetadata FusClient::check_firmware(const DownloadRequest& request) {
    const BinaryInform& info = fetch_binary_info(request.device.model, request.device.region);

    FirmwareMetadata metadata;
    metadata.version = info.version;
    metadata.filename = info.filename;
    metadata.size_bytes = info.size;
    metadata.os_version = request.manual_version.value_or("");
    return metadata;
}

std::string FusClient::create_download_url(const FirmwareMetadata&) const {
    return create_download_url();
}

std::vector<std::string> FusClient::make_headers(const bool include_cookie) const {
    const std::string authorization =
        "Authorization: FUS nonce=\"" + encnonce_ +
        "\", signature=\"" + auth_ +
        "\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"";

    std::vector<std::string> headers;
    headers.reserve(3);
    headers.push_back(authorization);
    headers.emplace_back(std::string("User-Agent: ") + kUserAgent);
    if (include_cookie && !sessid_.empty()) {
        headers.push_back("Cookie: JSESSIONID=" + sessid_);
    }
    return headers;
}

void FusClient::apply_response_state(const HttpResponse& response) {
    if (response.nonce.has_value() && !response.nonce->empty()) {
        encnonce_ = *response.nonce;
        nonce_ = auth::decryptnonce(encnonce_);
        auth_ = auth::getauth(nonce_);
    }

    for (const auto& cookie_header : response.set_cookie_headers) {
        const auto session_id = extract_jsessionid(cookie_header);
        if (session_id.has_value()) {
            sessid_ = *session_id;
            break;
        }
    }
}

FusClient::HttpResponse FusClient::make_post_request(
    const std::string& path,
    const std::string& body,
    const std::optional<long> timeout_seconds) {
    const std::string url = std::string(kApiBaseUrl) + path;
    auto curl = create_curl_handle();
    configure_common_options(curl.get());

    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str()),
        "Failed to configure POST URL");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_POST, 1L),
        "Failed to configure HTTP POST request");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.c_str()),
        "Failed to configure POST body");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size())),
        "Failed to configure POST body size");
    if (timeout_seconds.has_value()) {
        throw_if_curl_error(
            curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, *timeout_seconds),
            "Failed to configure POST timeout");
    }

    auto headers = make_headers(true);
    auto header_list = build_curl_header_list(headers);
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, header_list.get()),
        "Failed to set POST HTTP headers");

    std::string response_body;
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, append_to_string),
        "Failed to configure POST write callback");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response_body),
        "Failed to configure POST output target");

    HeaderCapture header_capture;
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, capture_headers),
        "Failed to configure POST header callback");
    throw_if_curl_error(
        curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &header_capture),
        "Failed to configure POST header output target");

    throw_if_curl_error(
        curl_easy_perform(curl.get()),
        "FUS POST request failed for " + path);

    const long status_code = get_response_code(curl.get(), "FUS POST request");
    if (status_code >= 400) {
        throw std::runtime_error(
            "FUS POST request failed for " + path + ": HTTP " + std::to_string(status_code) +
            " body=\"" + truncate_for_error(response_body) + "\"");
    }

    HttpResponse response;
    response.status_code = status_code;
    response.body = std::move(response_body);
    response.nonce = std::move(header_capture.nonce);
    response.set_cookie_headers = std::move(header_capture.set_cookie_headers);
    apply_response_state(response);
    return response;
}

} // namespace samloader
