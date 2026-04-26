#pragma once

#include "openssl.hpp"
#include "static_string.hpp"
#include <expected>
#include <string>

/**
 * @brief Wrapper for AES-256-GCM encryption and decryption operations.
 */
namespace crypto {
struct Aes256 {
public:
  /**
   * @brief Generates a new random 32-byte AES key and initializes the cipher
   * contexts
   *
   * @return
   * - Success: Generated Aes256
   * - Error: String error message
   */
  [[nodiscard]] static auto generate() -> std::expected<Aes256, std::string>;

  /**
   * @brief Creates an AES-256 cipher instance from an 32-byte @p key.
   *
   * @param key The 32-byte raw binary key string
   *
   * @return
   * - Success: An initialized Aes256 object using the provided @p key
   * - Error: String error message (e.g. if the @p key is not exactly 32 bytes)
   */
  [[nodiscard]] static auto fromKey(std::string_view key)
      -> std::expected<Aes256, std::string>;

  /**
   * @brief Encrypts @p data using the underlying key
   *
   * @note The resulting ciphertext string contains the randomly
   * generated Initialization Vector at the beginning, the actual encrypted in
   * the middle data, and the GCM authentication tag at the end.
   * | IV | DATA | GCM_TAG |
   *
   * @param data The data to encrypt
   *
   * @return
   * - Success: String containing the raw binary ciphertext
   * - Error: String error message
   */
  [[nodiscard]] auto encrypt(std::string_view data) const
      -> std::expected<std::string, std::string>;

  /**
   * @brief Decrypts ciphertext @p data using theunderlying key
   *
   * @param data The raw binary ciphertext (which must include the IV and
   * authentication tag) | IV | DATA | GCM_TAG|
   *
   * @return
   * - Success: String containing the decrypted data
   * - Error: String error message
   */
  [[nodiscard]] auto decrypt(std::string_view data) const
      -> std::expected<std::string, std::string>;

  /**
   * @brief Retrieves the raw 32-byte AES key.
   *
   * @return A reference to the interal 32-byte static_string containing the raw
   * data of the key key
   */
  [[nodiscard]] constexpr auto getRawKey() const noexcept
      -> const static_string<32> & {
    return rawKey_;
  }

private:
  static_string<32> rawKey_{};
  openssl::CipherCtxPointer encryptCtx_{nullptr};
  openssl::CipherCtxPointer decryptCtx_{nullptr};

  /**
   * Size of the initialization vector in bytes
   */
  static constexpr auto IV_SIZE = 12;
  /**
   * Size in bytes of GCM TAG appended to encrypte data.
   */
  static constexpr auto GCM_TAG_SIZE = 16;
};
} // namespace crypto
