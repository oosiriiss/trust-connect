#pragma once

#include "openssl.hpp"
#include "rsa.hpp"
#include "static_string.hpp"
#include <expected>

namespace crypto {

/**
 * @brief Wrapper for OpenSSL X509 certificate operations
 */
struct X509Certificate {
public:
  static constexpr auto SerialNumberBytes = 16;
  using SerialNumber = static_string<SerialNumberBytes>;

  /**
   * @brief Creates a self-signed CA (Certificate Authority) certificate
   *
   * @param name Common Name (CN) for the certificate
   * @param caKey RSA Key pair used to sign the certificate
   *
   * @return
   * - Success: X509Certificate representing the newly created CA
   * - Error: String error message
   */
  [[nodiscard]] static auto createSelfSignedCA(std::string_view name,
                                               const RsaKeyPair &caKey) noexcept
      -> std::expected<X509Certificate, std::string>;

  /**
   * @brief Parses an X509 certificate from a PEM-formatted string
   *
   * @param pem String view containing the PEM data
   *
   * @return
   * - Success: Parsed X509Certificate
   * - Error: String error message
   */
  [[nodiscard]] static auto fromPem(std::string_view pem) noexcept
      -> std::expected<X509Certificate, std::string>;

  /**
   * @brief Loads an X509 certificate from a file
   *
   * @param pathStr Path to the PEM certificate file
   *
   * @return
   * - Success: Loaded X509Certificate
   * - Error: String error message
   */
  [[nodiscard]] static auto fromFile(std::string_view pathStr)
      -> std::expected<X509Certificate, std::string>;

  /**
   * @brief Issues a new certificate signed by this CA certificate
   *
   * @param subjectKey RSA public key of the subject receiving the certificate
   * @param subjectName Common Name (CN) of the subject
   * @param caKey Private key of this CA used to sign the new certificate
   *
   * @return
   * - Success: Newly issued X509Certificate
   * - Error: String error message
   *
   * @ref RsaKeyPair
   */
  [[nodiscard]] auto issue(const RsaKeyPair &subjectKey,
                           std::string_view subjectName,
                           const RsaKeyPair &caKey) const noexcept
      -> std::expected<X509Certificate, std::string>;

  /**
   * @brief Converts the certificate to a PEM-formatted string
   *
   * @return
   * - Success: String containing the PEM representation
   * - Error: String error message
   */
  [[nodiscard]] auto toPem() const -> std::expected<std::string, std::string>;

  /**
   * @brief Saves the certificate to a file in PEM format
   *
   * @param pathStr Path where the certificate will be saved
   *
   * @return
   * - Success: std::nullopt
   * - Error: String error message
   */
  [[nodiscard]] auto saveToFile(std::string_view pathStr) const
      -> std::optional<std::string>;

  /**
   * @brief Verifies that a certificate was signed by this certificate
   *
   * @todo TODO :: Implement X509Store. This method currently only verifies the
   * math. It doesn't check for the certificate's expiration date, revocation,
   * etc.
   *
   * @param toVerify The certificate to be verified against this CA
   *
   * @return
   * - Success: Boolean set to true if certificate was issued by this CA or
   * false otherwise
   * - Error: String error message (if the verification process itself failed)
   */
  [[nodiscard]] auto verify(const X509Certificate &toVerify) const
      -> std::expected<bool, std::string>;
  /**
   * @brief Extracts the public key from the certificate
   *
   * @return
   * - Success: RsaKeyPair containing the public key
   * - Error: String error message
   */
  [[nodiscard]] auto getPublicKey() const noexcept
      -> std::expected<crypto::RsaKeyPair, std::string>;

  /**
   * @brief Extracts the Common Name from the certificate's subject
   *
   * @return
   * - Success: String containing the Common Name
   * - Error: String error message
   */
  [[nodiscard]] auto getCommonName() const
      -> std::expected<std::string, std::string>;

  /**
   * @brief Safely extracts the Common Name without returning an error
   *
   * @return String containing the Common Name or "Unknown" if the extraction
   * failed
   */
  [[nodiscard]] auto getCommonNameSafe() const -> std::string;

  /**
   * @brief Retrieves the certificate's serial number as a hex string
   *
   * @return
   * - Success: SerialNumber as a static string
   * - Error: String error message
   */
  [[nodiscard]] auto getSerialNumberHex() const
      -> std::expected<SerialNumber, std::string>;

  /**
   * @brief Returns the underlying X509 data pointer
   *
   * @return Raw pointer to the internal openssl::internal::X509 struct
   */
  [[nodiscard]] auto getRawCertificate() const noexcept
      -> openssl::internal::X509 *;

public:
  /**
   * OpenSSL X509 certificate in a smart pointer
   */
  openssl::X509Pointer x509{nullptr};
};
} // namespace crypto
