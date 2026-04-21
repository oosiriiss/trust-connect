#pragma once

#include "openssl.hpp"
#include "rsa.hpp"
#include "static_string.hpp"
#include <expected>

namespace crypto {
struct X509Certificate {
public:
  static constexpr auto SerialNumberBytes = 16;
  using SerialNumber = static_string<SerialNumberBytes>;

  [[nodiscard]] static auto createSelfSignedCA(std::string_view name,
                                               const RsaKeyPair &caKey) noexcept
      -> std::expected<X509Certificate, std::string>;

  [[nodiscard]] static auto fromPem(std::string_view pem) noexcept
      -> std::expected<X509Certificate, std::string>;

  [[nodiscard]] static auto fromFile(std::string_view pathStr)
      -> std::expected<X509Certificate, std::string>;

  [[nodiscard]] auto issue(const RsaKeyPair &subjectKey,
                           std::string_view subjectName,
                           const RsaKeyPair &caKey) const noexcept
      -> std::expected<X509Certificate, std::string>;

  [[nodiscard]] auto toPem() const -> std::expected<std::string, std::string>;

  [[nodiscard]] auto saveToFile(std::string_view pathStr) const
      -> std::optional<std::string>;

  // Verifies that the certificate was signed by this certificate
  //
  // TODO :: Implement X509Store.  This method only verifies the math. it
  // doesn't check for the certificate's expiration date etc.
  [[nodiscard]] auto verify(const X509Certificate &toVerify) const
      -> std::expected<bool, std::string>;

  [[nodiscard]] auto getPublicKey() const noexcept
      -> std::expected<crypto::RsaKeyPair, std::string>;

  [[nodiscard]] auto getCommonName() const
      -> std::expected<std::string, std::string>;
  [[nodiscard]] auto getCommonNameSafe() const -> std::string;

  [[nodiscard]] auto getSerialNumberHex() const
      -> std::expected<SerialNumber, std::string>;

  [[nodiscard]] auto getRawCertificate() const noexcept
      -> openssl::internal::X509 *;

public:
  openssl::X509Pointer x509{nullptr};
};
} // namespace crypto
