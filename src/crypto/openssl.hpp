#pragma once

#include "static_string.hpp"
#include <expected>
#include <memory>
#include <string>

extern "C" {
struct evp_pkey_st;
struct bio_st;
struct evp_pkey_ctx_st;
struct evp_md_ctx_st;
struct evp_cipher_ctx_st;
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
using Bio = struct ::bio_st;
struct BioDeleter {
  void operator()(Bio *bio) const noexcept;
};

using KeyCtx = struct ::evp_pkey_ctx_st;
struct KeyCtxDeleter {
  void operator()(KeyCtx *ctx) const noexcept;
};

using MdCtx = struct ::evp_md_ctx_st;
struct MdCtxDeleter {
  void operator()(MdCtx *ctx) const noexcept;
};

using CipherCtx = struct ::evp_cipher_ctx_st;
struct CipherCtxDeleter {
  void operator()(CipherCtx *cipher) const noexcept;
};

} // namespace internal

using RsaKeyPointer =
    std::unique_ptr<internal::RsaKey, internal::RsaKeyDeleter>;

using BioPointer = std::unique_ptr<internal::Bio, internal::BioDeleter>;

using KeyCtxPointer =
    std::unique_ptr<internal::KeyCtx, internal::KeyCtxDeleter>;

using MdCtxPointer = std::unique_ptr<internal::MdCtx, internal::MdCtxDeleter>;

using CipherCtxPointer =
    std::unique_ptr<internal::CipherCtx, internal::CipherCtxDeleter>;

} // namespace crypto::openssl
