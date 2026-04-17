#pragma once

#include "openssl.hpp"
#include <expected>
#include <openssl/evp.h>
#include <string>

namespace crypto {

struct RsaKeyPair {
public:
  static constexpr int KEY_BITS = 4096;

  [[nodiscard]] static auto generate()
      -> std::expected<RsaKeyPair, std::string>;

  [[nodiscard]] auto publicKeyPem() const
      -> std::expected<std::string, std::string>;
  [[nodiscard]] auto privateKeyPem() const
      -> std::expected<std::string, std::string>;

  openssl::RsaKeyPointer rawKey{nullptr};
};

} // namespace crypto
