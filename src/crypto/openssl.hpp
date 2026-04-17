#pragma once

#include "static_string.hpp"
#include <expected>
#include <memory>
#include <string>

extern "C" {
struct evp_pkey_st;
struct bio_st;
struct evp_pkey_ctx_st;
}

namespace crypto::openssl {
[[nodiscard]] auto getError() -> std::string;

/**
 * Allowed byte sizes are: 16, 32, 64
 */
template <std::size_t Bytes>
[[nodiscard]] auto generateRandomBytes() noexcept
    -> std::expected<static_string<Bytes>, std::string>;

namespace internal {
using RsaKey = struct ::evp_pkey_st;
struct RsaKeyDeleter {
  void operator()(RsaKey *key) const noexcept;
};

} // namespace internal
using RsaKeyPointer =
    std::unique_ptr<internal::RsaKey, internal::RsaKeyDeleter>;

namespace internal {
using Bio = struct ::bio_st;
struct BioDeleter {
  void operator()(Bio *bio) const noexcept;
};

} // namespace internal
using BioPointer = std::unique_ptr<internal::Bio, internal::BioDeleter>;

namespace internal {
using Ctx = struct ::evp_pkey_ctx_st;
struct CtxDeleter {
  void operator()(Ctx *ctx) const noexcept;
};

} // namespace internal
using CtxPointer = std::unique_ptr<internal::Ctx, internal::CtxDeleter>;

} // namespace crypto::openssl
