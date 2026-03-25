#pragma once

#include <optional>
#include <string>
#include <unordered_map>

#include "samloader/types.hpp"

namespace samloader::xml {

std::string get_logic_check(const std::string& inp, const std::string& nonce);
std::string BuildBinaryInformRequestXml(const std::string& model, const std::string& region);
std::string BuildBinaryInitRequestXml(const std::string& filename, const std::string& nonce);
std::optional<std::unordered_map<std::string, std::string>> ParseXmlData(const std::string& xml);
std::optional<BinaryInform> ParseBinaryInform(const std::string& xml);

inline std::string build_binary_inform_request_xml(const std::string& model, const std::string& region) {
    return BuildBinaryInformRequestXml(model, region);
}

inline std::string build_binary_init_request_xml(const std::string& filename, const std::string& nonce) {
    return BuildBinaryInitRequestXml(filename, nonce);
}

inline std::optional<std::unordered_map<std::string, std::string>> parse_xml_data(const std::string& xml) {
    return ParseXmlData(xml);
}

inline std::optional<BinaryInform> parse_binary_inform(const std::string& xml) {
    return ParseBinaryInform(xml);
}

} // namespace samloader::xml
