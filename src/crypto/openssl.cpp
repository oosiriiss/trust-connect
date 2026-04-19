#include "openssl.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <array>
#include <string_view>
namespace crypto::openssl {
auto getError() -> std::string {

  std::string error{"Unknown OpenSSL Error"};

  unsigned long errorCode = -1; // NOLINT google-runtime-in
  std::array<char, 512> buffer{};

  while ((errorCode = ERR_get_error()) != 0) {
    ERR_error_string_n(errorCode, buffer.data(), buffer.size());

    error += std::string_view{buffer.begin(), buffer.end()};
    error += '\n';
  }

  return error;
}

template <std::size_t Bytes>
[[nodiscard]] auto generateRandomBytes() noexcept
    -> std::expected<static_string<Bytes>, std::string> {

  std::expected<static_string<Bytes>, std::string> output{
      static_string<Bytes>{}};

  if (RAND_bytes(
          reinterpret_cast<unsigned char *>(output->data.data()), // NOLINT
          Bytes) == 0) {
    return std::unexpected(std::format("RAND_bytes failed: {}", getError()));
  }
  return output;
}

// Explicit instantiations
template auto generateRandomBytes<12>()
    -> std::expected<static_string<12>, std::string>;

template auto generateRandomBytes<16>()
    -> std::expected<static_string<16>, std::string>;

template auto generateRandomBytes<32>()
    -> std::expected<static_string<32>, std::string>;

template auto generateRandomBytes<64>()
    -> std::expected<static_string<64>, std::string>;

namespace internal {

void RsaKeyDeleter::operator()(RsaKey *key) const noexcept {
  if (key == nullptr) {
    return;
  }
  EVP_PKEY_free(key);
}

void BioDeleter::operator()(Bio *bio) const noexcept {
  if (bio == nullptr) {
    return;
  }

  BIO_free(bio);
}

void KeyCtxDeleter::operator()(KeyCtx *ctx) const noexcept {
  if (ctx == nullptr) {
    return;
  }

  ::EVP_PKEY_CTX_free(ctx);
}

void MdCtxDeleter::operator()(MdCtx *ctx) const noexcept {
  if (ctx == nullptr) {
    return;
  }
  EVP_MD_CTX_free(ctx);
}

void CipherCtxDeleter::operator()(CipherCtx *cipher) const noexcept {
  if (cipher == nullptr) {
    return;
  }

  EVP_CIPHER_CTX_free(cipher);
}

} // namespace internal
} // namespace crypto::openssl
