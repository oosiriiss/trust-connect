#include "crypto.hpp"

#include "debug_utils.hpp"
#include "logzy/logzy.hpp"
#include <expected>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace crypto {

template <std::size_t Bytes>
[[nodiscard]] static auto generateRandomBytes() noexcept
    -> std::expected<static_string<Bytes>, std::string> {

  std::expected<static_string<Bytes>, std::string> output{
      static_string<Bytes>{}};

  if (RAND_bytes(
          reinterpret_cast<unsigned char *>(output->data.data()), // NOLINT
          Bytes) == 0) {
    return std::unexpected(std::string("RAND_bytes failed"));
  }
  return output;
}

template std::expected<Hash32, std::string> generateRandomBytes<32>();

[[nodiscard]] auto sha256(std::string_view input) noexcept
    -> std::expected<Hash32, std::string> {

  std::expected<Hash32, std::string> output{Hash32{}};
  unsigned int length = 0;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return std::unexpected(std::string("sha256 :: EVP_MD_CTX_new failed"));
  }

  if (EVP_DigestInit(ctx, EVP_sha256()) == 0) {
    return std::unexpected(std::string("sha256 :: EVP_DigestInit failed"));
  }

  if (EVP_DigestUpdate(ctx, input.data(), input.size()) == 0) {
    return std::unexpected(std::string("sha256 :: EVP_DigetsUpdate failed"));
  }

  if (EVP_DigestFinal(
          ctx,
          reinterpret_cast<unsigned char *>(output->data.data()), // NOLINT
          &length) == 0) {
    return std::unexpected(std::string("sha256 :: EVP_DigestFinal failed"));
  }

  EVP_MD_CTX_free(ctx);
  DEBUG_ASSERT(length == 32);
  return output;
}

[[nodiscard]] auto generateRandomId(std::string_view seed) noexcept
    -> std::expected<Hash32, std::string> {

  logzy::trace("Generating random ID for: {}", seed);

  auto randomBytes = generateRandomBytes<32>();
  if (!randomBytes) {
    return std::unexpected(std::format(
        "generateRandomId :: Generating random 32 bytes failed. Reason {}",
        randomBytes.error()));
  }

  std::string buffer;
  buffer.reserve(64);
  buffer.append(seed);
  buffer.append(
      std::string_view{randomBytes->data.begin(), randomBytes->data.end()});

  return sha256(buffer);
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
