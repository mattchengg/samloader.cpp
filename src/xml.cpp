#include "samloader/xml.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <array>
#include <unordered_map>
#include <utility>
#include <vector>

namespace samloader::xml {

namespace {

void log_parse_error(std::string_view message) {
    std::cerr << "XML parse error: " << message << '\n';
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, (last - first) + 1);
}

std::optional<std::string> extract_first_tag_value(
    const std::string& xml,
    const std::string& tag,
    const std::size_t from = 0U) {
    const std::string open = "<" + tag + ">";
    const std::string close = "</" + tag + ">";
    const std::size_t start = xml.find(open, from);
    if (start == std::string::npos) {
        return std::nullopt;
    }
    const std::size_t content_start = start + open.size();
    const std::size_t end = xml.find(close, content_start);
    if (end == std::string::npos || end < content_start) {
        return std::nullopt;
    }
    return xml.substr(content_start, end - content_start);
}

std::optional<std::string> extract_first_data_value(
    const std::string& xml,
    const std::string& tag) {
    const std::string open = "<" + tag + ">";
    const std::string close = "</" + tag + ">";
    const std::size_t start = xml.find(open);
    if (start == std::string::npos) {
        return std::nullopt;
    }
    const std::size_t body_start = start + open.size();
    const std::size_t end = xml.find(close, body_start);
    if (end == std::string::npos || end < body_start) {
        return std::nullopt;
    }
    const std::string body = xml.substr(body_start, end - body_start);
    return extract_first_tag_value(body, "Data");
}

std::optional<std::vector<std::uint8_t>> md5_digest(const std::string& input) {
    EVP_MD_CTX* raw_ctx = EVP_MD_CTX_new();
    if (raw_ctx == nullptr) {
        return std::nullopt;
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(raw_ctx, EVP_MD_CTX_free);

    if (EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) != 1) {
        return std::nullopt;
    }
    if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
        return std::nullopt;
    }

    unsigned int digest_len = EVP_MAX_MD_SIZE;
    std::vector<std::uint8_t> digest(digest_len);
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1) {
        return std::nullopt;
    }
    digest.resize(digest_len);
    return digest;
}

} // namespace

std::string get_logic_check(const std::string& inp, const std::string& nonce) {
    std::string out;
    out.reserve(nonce.size());
    for (unsigned char c : nonce) {
        const std::size_t idx = static_cast<std::size_t>(c & 0xF);
        if (idx >= inp.size()) {
            throw std::out_of_range("get_logic_check index out of range");
        }
        out.push_back(inp[idx]);
    }
    return out;
}

std::string BuildBinaryInformRequestXml(const std::string& model, const std::string& region) {
    return "<FUSMsg>\n"
           "<FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr>\n"
           "<FUSBody>\n"
           "    <Put>\n"
           "        <ACCESS_MODE><Data>5</Data></ACCESS_MODE>\n"
           "        <BINARY_NATURE><Data>1</Data></BINARY_NATURE>\n"
           "        <CLIENT_PRODUCT><Data>Smart Switch</Data></CLIENT_PRODUCT>\n"
           "        <CLIENT_VERSION><Data>5.0.0.0</Data></CLIENT_VERSION>\n"
           "        <DEVICE_FW_VERSION><Data>................</Data></DEVICE_FW_VERSION>\n"
           "        <DEVICE_LOCAL_CODE><Data>" +
           region +
           "</Data></DEVICE_LOCAL_CODE>\n"
           "        <DEVICE_AID_CODE><Data>" +
           region +
           "</Data></DEVICE_AID_CODE>\n"
           "        <DEVICE_CC_CODE><Data>DE</Data></DEVICE_CC_CODE>\n"
           "        <DEVICE_MODEL_NAME><Data>" +
           model +
           "</Data></DEVICE_MODEL_NAME>\n"
           "        <LOGIC_CHECK><Data>................</Data></LOGIC_CHECK>\n"
           "        <DEVICE_INITIALIZE><Data>2</Data></DEVICE_INITIALIZE>\n"
           "    </Put>\n"
           "</FUSBody>\n"
           "</FUSMsg>";
}

std::string BuildBinaryInitRequestXml(const std::string& filename, const std::string& nonce) {
    const std::size_t dot = filename.find('.');
    const std::string name_part = (dot == std::string::npos) ? filename : filename.substr(0, dot);
    const std::size_t start = (name_part.size() > 16) ? (name_part.size() - 16) : 0;
    const std::string check_input = name_part.substr(start);
    const std::string logic_check = get_logic_check(check_input, nonce);

    return "<FUSMsg>\n"
           "<FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr>\n"
           "<FUSBody>\n"
           "    <Put>\n"
           "        <BINARY_FILE_NAME><Data>" +
           filename +
           "</Data></BINARY_FILE_NAME>\n"
           "        <LOGIC_CHECK><Data>" +
           logic_check +
           "</Data></LOGIC_CHECK>\n"
           "    </Put>\n"
           "</FUSBody>\n"
           "</FUSMsg>";
}

std::optional<std::unordered_map<std::string, std::string>> ParseXmlData(const std::string& xml) {
    const auto status_value = extract_first_tag_value(xml, "Status");
    if (!status_value.has_value()) {
        log_parse_error("missing Status");
        return std::nullopt;
    }

    const std::string status_text = trim(*status_value);
    char* end = nullptr;
    errno = 0;
    const long status = std::strtol(status_text.c_str(), &end, 10);
    if (errno != 0 || end == status_text.c_str() || (end != nullptr && *end != '\0')) {
        log_parse_error("Status is not a valid integer");
        return std::nullopt;
    }
    if (status != 200) {
        return std::nullopt;
    }

    static const std::array<const char*, 5> required_keys{
        "BINARY_BYTE_SIZE",
        "LATEST_FW_VERSION",
        "LOGIC_VALUE_FACTORY",
        "BINARY_NAME",
        "MODEL_PATH",
    };

    std::unordered_map<std::string, std::string> kv;
    for (const char* key : required_keys) {
        const auto value = extract_first_data_value(xml, key);
        if (!value.has_value()) {
            log_parse_error(std::string("missing required field: ") + key);
            return std::nullopt;
        }
        kv[key] = trim(*value);
    }

    return kv;
}

std::optional<BinaryInform> ParseBinaryInform(const std::string& xml) {
    auto kv = ParseXmlData(xml);
    if (!kv.has_value()) {
        return std::nullopt;
    }

    const auto size_it = kv->find("BINARY_BYTE_SIZE");
    const auto version_it = kv->find("LATEST_FW_VERSION");
    const auto logic_it = kv->find("LOGIC_VALUE_FACTORY");
    const auto filename_it = kv->find("BINARY_NAME");
    const auto path_it = kv->find("MODEL_PATH");
    if (size_it == kv->end() || version_it == kv->end() || logic_it == kv->end() ||
        filename_it == kv->end() || path_it == kv->end()) {
        log_parse_error("required BinaryInform field missing");
        return std::nullopt;
    }

    std::uint64_t size = 0;
    try {
        std::size_t consumed = 0;
        const auto parsed = std::stoull(size_it->second, &consumed, 10);
        if (consumed != size_it->second.size()) {
            log_parse_error("BINARY_BYTE_SIZE contains invalid characters");
            return std::nullopt;
        }
        size = static_cast<std::uint64_t>(parsed);
    } catch (const std::exception&) {
        log_parse_error("BINARY_BYTE_SIZE is not a valid u64");
        return std::nullopt;
    }

    std::string key_input;
    try {
        key_input = get_logic_check(version_it->second, logic_it->second);
    } catch (const std::exception& ex) {
        log_parse_error(ex.what());
        return std::nullopt;
    }

    auto digest = md5_digest(key_input);
    if (!digest.has_value()) {
        log_parse_error("failed to compute md5 digest");
        return std::nullopt;
    }

    BinaryInform info;
    info.version = version_it->second;
    info.filename = filename_it->second;
    info.path = path_it->second;
    info.size = size;
    info.key = std::move(*digest);
    return info;
}

} // namespace samloader::xml
