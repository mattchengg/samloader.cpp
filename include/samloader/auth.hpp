#pragma once

#include <string>

namespace samloader::auth {

std::string derive_key(const std::string& nonce);
std::string getauth(const std::string& nonce);
std::string decryptnonce(const std::string& input);
void run_smoke_test();

} // namespace samloader::auth
