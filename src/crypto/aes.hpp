#pragma once

#include "openssl.hpp"
#include "static_string.hpp"
#include <expected>
#include <string>

namespace crypto {
struct Aes256 {
public:
  [[nodiscard]] static auto generate() -> std::expected<Aes256, std::string>;

  [[nodiscard]] static auto fromKey(std::string_view key)
      -> std::expected<Aes256, std::string>;

  [[nodiscard]] auto encrypt(std::string_view data)
      -> std::expected<std::string, std::string>;

  [[nodiscard]] auto decrypt(std::string_view data)
      -> std::expected<std::string, std::string>;

  [[nodiscard]] constexpr auto getRawKey() const noexcept
      -> const static_string<32> & {
    return rawKey_;
  }

private:
  static_string<32> rawKey_{};
  openssl::CipherCtxPointer encryptCtx_{nullptr};
  openssl::CipherCtxPointer decryptCtx_{nullptr};

  static constexpr auto IV_SIZE = 12;
  static constexpr auto GCM_TAG_SIZE = 16;
};
} // namespace crypto
