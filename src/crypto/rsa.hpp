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

  [[nodiscard]] static auto fromPrivatePem(std::string_view privatePem)
      -> std::expected<RsaKeyPair, std::string>;
  [[nodiscard]] static auto fromPublicPem(std::string_view publicPem)
      -> std::expected<RsaKeyPair, std::string>;

  [[nodiscard]] auto publicKeyPem() const
      -> std::expected<std::string, std::string>;
  [[nodiscard]] auto privateKeyPem() const
      -> std::expected<std::string, std::string>;

  [[nodiscard]] auto encryptPublic(std::string_view plain) const
      -> std::expected<std::string, std::string>;

  [[nodiscard]] auto decryptPrivate(std::string_view cipher) const
      -> std::expected<std::string, std::string>;

  openssl::RsaKeyPointer rawKey{nullptr};
};

} // namespace crypto
