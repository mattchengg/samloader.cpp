#include "samloader/auth.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>

namespace samloader::auth {

namespace {

constexpr std::string_view KEY_1 = "vicopx7dqu06emacgpnpy8j8zwhduwlh";
constexpr std::string_view KEY_2 = "9u7qab84rpc16gvk";

std::runtime_error openssl_error(const std::string& action) {
    std::array<char, 256> buffer{};
    const unsigned long code = ERR_get_error();
    if (code == 0UL) {
        return std::runtime_error(action + " failed");
    }
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return std::runtime_error(action + " failed: " + std::string(buffer.data()));
}

std::vector<std::uint8_t> to_bytes(std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::string base64_encode(const std::vector<std::uint8_t>& input) {
    const int output_len = 4 * static_cast<int>((input.size() + 2U) / 3U);
    std::string encoded(static_cast<std::size_t>(output_len), '\0');
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(encoded.data()),
        input.data(),
        static_cast<int>(input.size()));
    if (written < 0) {
        throw std::runtime_error("base64 encode failed");
    }
    encoded.resize(static_cast<std::size_t>(written));
    return encoded;
}

std::vector<std::uint8_t> base64_decode(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    if ((input.size() % 4U) != 0U) {
        throw std::runtime_error("base64 decode failed: invalid input length");
    }

    std::vector<std::uint8_t> decoded((input.size() / 4U) * 3U);
    const int written = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<const unsigned char*>(input.data()),
        static_cast<int>(input.size()));
    if (written < 0) {
        throw std::runtime_error("base64 decode failed: invalid character");
    }

    std::size_t padding = 0;
    if (!input.empty() && input.back() == '=') {
        padding = 1;
        if (input.size() > 1 && input[input.size() - 2] == '=') {
            padding = 2;
        }
    }
    if (static_cast<std::size_t>(written) < padding) {
        throw std::runtime_error("base64 decode failed: invalid padding");
    }
    decoded.resize(static_cast<std::size_t>(written) - padding);
    return decoded;
}

std::vector<std::uint8_t> aes_256_cbc_encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 16>& iv) {
    EVP_CIPHER_CTX* raw_ctx = EVP_CIPHER_CTX_new();
    if (raw_ctx == nullptr) {
        throw std::runtime_error("aes encrypt failed: could not allocate context");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw_ctx, EVP_CIPHER_CTX_free);

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw openssl_error("aes encrypt init");
    }

    std::vector<std::uint8_t> ciphertext(plaintext.size() + 16U);
    int out_len = 0;
    if (EVP_EncryptUpdate(
            ctx.get(),
            ciphertext.data(),
            &out_len,
            plaintext.data(),
            static_cast<int>(plaintext.size())) != 1) {
        throw openssl_error("aes encrypt update");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len) != 1) {
        throw openssl_error("aes encrypt final");
    }
    ciphertext.resize(static_cast<std::size_t>(out_len + final_len));
    return ciphertext;
}

std::vector<std::uint8_t> aes_256_cbc_decrypt(
    const std::vector<std::uint8_t>& ciphertext,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 16>& iv) {
    EVP_CIPHER_CTX* raw_ctx = EVP_CIPHER_CTX_new();
    if (raw_ctx == nullptr) {
        throw std::runtime_error("aes decrypt failed: could not allocate context");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw_ctx, EVP_CIPHER_CTX_free);

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw openssl_error("aes decrypt init");
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size() + 16U);
    int out_len = 0;
    if (EVP_DecryptUpdate(
            ctx.get(),
            plaintext.data(),
            &out_len,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())) != 1) {
        throw openssl_error("aes decrypt update");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &final_len) != 1) {
        throw openssl_error("aes decrypt final");
    }
    plaintext.resize(static_cast<std::size_t>(out_len + final_len));
    return plaintext;
}

bool is_valid_utf8(const std::vector<std::uint8_t>& data) {
    std::size_t index = 0;
    while (index < data.size()) {
        const std::uint8_t byte = data[index];
        std::size_t extra_bytes = 0;
        if ((byte & 0x80U) == 0U) {
            extra_bytes = 0;
        } else if ((byte & 0xE0U) == 0xC0U) {
            extra_bytes = 1;
            if (byte < 0xC2U) {
                return false;
            }
        } else if ((byte & 0xF0U) == 0xE0U) {
            extra_bytes = 2;
        } else if ((byte & 0xF8U) == 0xF0U) {
            extra_bytes = 3;
            if (byte > 0xF4U) {
                return false;
            }
        } else {
            return false;
        }

        if (index + extra_bytes >= data.size()) {
            return false;
        }
        for (std::size_t i = 1; i <= extra_bytes; ++i) {
            if ((data[index + i] & 0xC0U) != 0x80U) {
                return false;
            }
        }
        index += extra_bytes + 1;
    }
    return true;
}

std::array<std::uint8_t, 32> key_from_string(const std::string& key) {
    if (key.size() != 32U) {
        throw std::runtime_error("invalid AES-256 key length; expected 32 bytes");
    }
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(key[i]);
    }
    return out;
}

std::array<std::uint8_t, 16> iv_from_key_prefix(const std::string& key) {
    if (key.size() < 16U) {
        throw std::runtime_error("invalid IV source length; expected at least 16 bytes");
    }
    std::array<std::uint8_t, 16> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(key[i]);
    }
    return out;
}

} // namespace

std::string derive_key(const std::string& nonce) {
    std::string key;
    key.reserve(32U);
    for (std::size_t i = 0; i < nonce.size() && i < 16U; ++i) {
        const unsigned char c = static_cast<unsigned char>(nonce[i]);
        const std::size_t idx = static_cast<std::size_t>(c % 16U);
        key.push_back(KEY_1[idx]);
    }
    key.append(KEY_2);
    return key;
}

std::string getauth(const std::string& nonce) {
    const std::string derived = derive_key(nonce);
    const auto key = key_from_string(derived);
    const auto iv = iv_from_key_prefix(derived);
    const auto ciphertext = aes_256_cbc_encrypt(to_bytes(nonce), key, iv);
    return base64_encode(ciphertext);
}

std::string decryptnonce(const std::string& input) {
    const auto encrypted = base64_decode(input);
    const std::string key_string(KEY_1);
    const auto key = key_from_string(key_string);
    const auto iv = iv_from_key_prefix(key_string);
    const auto decrypted = aes_256_cbc_decrypt(encrypted, key, iv);
    if (!is_valid_utf8(decrypted)) {
        throw std::runtime_error("decryptnonce failed: decrypted payload is not valid UTF-8");
    }
    return std::string(decrypted.begin(), decrypted.end());
}

void run_smoke_test() {
    const std::string nonce = "0123456789abcdef";
    const std::string expected_key = "vicopx7dquicopx79u7qab84rpc16gvk";
    const std::string expected_auth = "KM8PEJk/tIE0El5Rx4+tIftq2qDyWCFcNDPD+6jK9FE=";
    const std::string encrypted_nonce = "7fbdcfDEF1JDl/26GEOEqV9qNggH7NNceMDjPhwLCZw=";

    if (derive_key(nonce) != expected_key) {
        throw std::runtime_error("auth smoke test failed: derive_key mismatch");
    }
    if (getauth(nonce) != expected_auth) {
        throw std::runtime_error("auth smoke test failed: getauth mismatch");
    }
    if (decryptnonce(encrypted_nonce) != nonce) {
        throw std::runtime_error("auth smoke test failed: decryptnonce mismatch");
    }
}

} // namespace samloader::auth
