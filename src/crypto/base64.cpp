#include "base64.hpp"
#include "crypto/openssl.hpp"
#include "openssl.hpp"
#include <expected>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace crypto {
[[nodiscard]] auto base64Encode(std::string_view data)
    -> std::expected<std::string, std::string> {

  auto bio = openssl::BioPointer{BIO_new(BIO_f_base64())};

  if (bio == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create BIO for Base64 encode. {}", openssl::getError()));
  }

  BIO_set_flags(bio.get(), BIO_FLAGS_BASE64_NO_NL);

  auto mem = openssl::BioPointer(BIO_new(BIO_s_mem()));

  if (mem == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create mem for base64 encode. {}", openssl::getError()));
  }

  BIO_push(bio.get(), mem.get());
  BIO_write(bio.get(), data.data(), static_cast<int>(data.size()));

  BIO_flush(bio.get());

  BUF_MEM *memBuf = nullptr;
  BIO_get_mem_ptr(mem.get(), &memBuf);

  return std::expected<std::string, std::string>(
      std::string(memBuf->data, memBuf->length));
}

[[nodiscard]] auto base64Decode(std::string_view encoded)
    -> std::expected<std::string, std::string> {

  auto bio = openssl::BioPointer{BIO_new(BIO_f_base64())};

  if (bio == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create BIO for Base64 decode. {}", openssl::getError()));
  }
  BIO_set_flags(bio.get(), BIO_FLAGS_BASE64_NO_NL);

  auto mem = openssl::BioPointer{
      BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()))};

  if (mem == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create mem for Base64 decode. {}", openssl::getError()));
  }

  BIO_push(bio.get(), mem.get());
  std::expected<std::string, std::string> buffer(
      std::string(encoded.size(), '\0'));

  const int length =
      BIO_read(bio.get(), buffer->data(), static_cast<int>(buffer->size()));
  if (length < 0) {
    return std::unexpected(
        std::format("Base64 decode failed. {}", openssl::getError()));
  }

  buffer->resize(length);
  return buffer;
}
} // namespace crypto
