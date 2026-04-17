#include "hash.hpp"
#include "debug_utils.hpp"

#include "openssl.hpp"
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace crypto {

[[nodiscard]] auto sha256(std::string_view input) noexcept
    -> std::expected<Hash32, std::string> {

  std::expected<Hash32, std::string> output{Hash32{}};
  unsigned int length = 0;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return std::unexpected(std::format("sha256 :: EVP_MD_CTX_new failed: {}",
                                       openssl::getError()));
  }

  if (EVP_DigestInit(ctx, EVP_sha256()) == 0) {
    return std::unexpected(std::format("sha256 :: EVP_DigestInit failed: {}",
                                       openssl::getError()));
  }

  if (EVP_DigestUpdate(ctx, input.data(), input.size()) == 0) {
    return std::unexpected(std::format("sha256 :: EVP_DigetsUpdate failed: {}",
                                       openssl::getError()));
  }

  if (EVP_DigestFinal(
          ctx,
          reinterpret_cast<unsigned char *>(output->data.data()), // NOLINT
          &length) == 0) {
    return std::unexpected(std::format("sha256 :: EVP_DigestFinal failed: {}",
                                       openssl::getError()));
  }

  EVP_MD_CTX_free(ctx);
  DEBUG_ASSERT(length == 32);
  return output;
}

[[nodiscard]] auto hashToHex(const Hash32 &hash) noexcept -> std::string {

  static_assert(hash.size() == 32);
  std::string out;
  out.reserve(hash.size() * 2);

  for (auto byte : hash) {
    out += std::format("{:02x}", byte);
  }

  return out;
}
} // namespace crypto
