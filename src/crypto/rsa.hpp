#pragma once

#include "openssl.hpp"
#include <expected>
#include <openssl/evp.h>
#include <string>

namespace crypto {

/**
 * @brief Wrapper for RSA key pair generation, encryption, signing, and
 * verification.
 */
struct RsaKeyPair {
public:
  /**
   * @brief Default size of the RSA key in bits.
   */
  static constexpr int KEY_BITS = 4096;

  /**
   * @brief Generates a new RSA key pair.
   *
   * @return
   * - Success: Generated RsaKeyPair
   * - Error: String error message
   */
  [[nodiscard]] static auto generate()
      -> std::expected<RsaKeyPair, std::string>;

  /**
   * @brief Parses an RSA key pair from a private key PEM-formatted string.
   *
   * @param privatePem String view containing the private key PEM data
   *
   * @return
   * - Success: Parsed RsaKeyPair (containing both private and public parts)
   * - Error: String error message
   */
  [[nodiscard]] static auto fromPrivatePem(std::string_view privatePem)
      -> std::expected<RsaKeyPair, std::string>;

  /**
   * @brief Parses an RSA public key from a public key PEM-formatted string.
   *
   * @note The resulting RsaKeyPair will only contain the public key. Methods
   * requiring a private key (like signing or decrypting) will fail.
   *
   * @param publicPem String view containing the public key PEM data
   *
   * @return
   * - Success: Parsed RsaKeyPair (public key only)
   * - Error: String error message
   */
  [[nodiscard]] static auto fromPublicPem(std::string_view publicPem)
      -> std::expected<RsaKeyPair, std::string>;

  /**
   * @brief Signs data using the RSA private key.
   *
   * @param data The plaintext data or hash to be signed
   *
   * @return
   * - Success: String containing the raw binary signature
   * - Error: String error message
   */
  [[nodiscard]] auto sign(std::string_view data) const noexcept
      -> std::expected<std::string, std::string>;

  /**
   * @brief Verifies a signature using the RSA public key.
   *
   * @param data The original data that was signed
   * @param] signature The raw binary signature to verify against the data
   *
   * @return
   * - Success: Boolean set to true if the signature is valid and matches the
   * data, false otherwise
   * - Error: String error message (if the cryptographic operations itself
   * failed)
   */
  [[nodiscard]] auto verify(std::string_view data,
                            std::string_view signature) const noexcept
      -> std::expected<bool, std::string>;

  /**
   * @brief Exports the public key to a PEM-formatted string.
   *
   * @return
   * - Success: String containing the public key PEMrepresentation

   * - Error: String error message
   */
  [[nodiscard]] auto publicKeyPem() const
      -> std::expected<std::string, std::string>;

  /**
   * @brief Exports the private key to a PEM-formatted string.
   *
   * @return
   * - Success: String containing the private key PEM representation
   * - Error: String error message
   */
  [[nodiscard]] auto privateKeyPem() const
      -> std::expected<std::string, std::string>;

  /**
   * @brief Encrypts plaintext data using the public key
   *
   * @param plain The plaintext data to encrypt
   *
   * @return
   * - Success: String containing the raw binary ciphertext
   * - Error: String error message
   */
  [[nodiscard]] auto encryptPublic(std::string_view plain) const
      -> std::expected<std::string, std::string>;

  /**
   * @brief Decrypts ciphertext data using the RSA private key.
   *
   * @param cipher The raw binary ciphertext to decrypt
   *
   * @return
   * - Success: String containing the decrypted plaintext
   * - Error: String error message
   */
  [[nodiscard]] auto decryptPrivate(std::string_view cipher) const
      -> std::expected<std::string, std::string>;

  openssl::RsaKeyPointer rawKey{nullptr};
};

} // namespace crypto
