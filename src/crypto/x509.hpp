#pragma once

#include "openssl.hpp"
#include "rsa.hpp"
#include <expected>

namespace crypto {
struct X509Certificate {
public:
  [[nodiscard]] static auto createSelfSignedCA(std::string_view name,
                                               const RsaKeyPair &caKey) noexcept
      -> std::expected<X509Certificate, std::string>;

  [[nodiscard]] auto issue(const RsaKeyPair &subjectKey,
                           std::string_view subjectName,
                           const RsaKeyPair &caKey) const noexcept
      -> std::expected<X509Certificate, std::string>;

  [[nodiscard]] auto toPem() const -> std::expected<std::string, std::string>;
  [[nodiscard]] static auto fromPem(std::string_view pem) noexcept
      -> std::expected<X509Certificate, std::string>;

  // Verifies that the certificate was signed by this certificate
  //
  // TODO :: Implement X509Store.  This method only verifies the math. it
  // doesn't check for the certificate's expiration date etc.
  [[nodiscard]] auto verify(const X509Certificate &toVerify) const
      -> std::expected<bool, std::string>;

  [[nodiscard]] auto getRawCertificate() const noexcept
      -> openssl::internal::X509 *;

  [[nodiscard]] auto getCommonName() const
      -> std::expected<std::string, std::string>;
  [[nodiscard]] auto getCommonNameSafe() const -> std::string;

  [[nodiscard]] auto getSerialNumberHex() const
      -> std::expected<std::string, std::string>;

public:
  openssl::X509Pointer x509{nullptr};

private:
  // One CA cannot (or shouldn't) issue multiple certs with the same serial
  // number. Generating a random BIGNUM wiht openssl's BN would be better, but
  // its ok for now
  inline static int X509SerialNumbercounter = 1; // NOLINT
};
} // namespace crypto
