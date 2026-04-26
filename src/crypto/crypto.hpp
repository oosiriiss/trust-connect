#pragma once

#include "crypto/aes.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "hash.hpp"
#include "nlohmann/json_fwd.hpp"
#include <string>

namespace crypto {

/**
 * @brief Generates a new random ID from a given @p seed combined with some
 * random bytes, so it is no the same everytime
 *
 * @param seed The base string used to seed the generation
 *
 * @return
 * - Success: Hash32 containing ID
 * - Error: String error message
 */
[[nodiscard]] auto generateRandomId(std::string_view seed) noexcept
    -> std::expected<Hash32, std::string>;

/**
 * @brief Encrypts plaintext @p data using an RSA public @p key and encodes the
 * result in Base64.
 *
 * @param data The plaintext data to be encrypted
 * @param key The RSA key pair used for encryption
 *
 * @return
 * - Success: Base64 encoded string of the encrypted ciphertext
 * - Error: String error message
 */
auto encryptAndEncode(std::string_view data, const crypto::RsaKeyPair &key)
    -> std::expected<std::string, std::string>;

/**
 * @brief Decodes a Base64 string @p encrypted and decrypts the content using an
 * RSA private @p key.
 *
 * @param encrypted The Base64 encoded ciphertext string
 * @param key The RSA key pair used for decryption
 *
 * @return
 * - Success: String containing the decrypted plaintext
 * - Error: String error message
 */
auto decodeAndDecrypt(std::string_view encrypted, const crypto::RsaKeyPair &key)
    -> std::expected<std::string, std::string>;

/**
 * @brief Encrypts plaintext @p data using AES-256 GCM @p key and encodes the
 * result in Base64.
 *
 * @param data The plaintext data to be encrypted
 * @param key The AES-256 GCM key used for encryption
 *
 * @return
 * - Success: Base64 encoded string of the encrypted ciphertext
 * - Error: String error message
 */
auto encryptAndEncode(std::string_view data, const crypto::Aes256 &key)
    -> std::expected<std::string, std::string>;

/**
 * @brief Decodes a Base64 string @p encrypted and decrypts the content using an
 * AES-256 @p key.
 *
 * @param encrypted The Base64 encoded ciphertext string
 * @param key The AES-256 GCM key used for decryption
 *
 * @return
 * - Success: String containing the decrypted plaintext
 * - Error: String error message
 */
auto decodeAndDecrypt(std::string_view encrypted, const crypto::Aes256 &key)
    -> std::expected<std::string, std::string>;

/**
 * @brief Signs the json paydload by adding it a "signature" field
 *
 * @param privateKey The RSA key pair used for signing
 * @param payload The JSON object to be signed
 *
 * @return
 * - Success: std::nullopt
 * - Error: String error message
 */
auto signPayload(const RsaKeyPair &privateKey, nlohmann::json &payload)
    -> std::optional<std::string>;

/**
 * @brief Verifies the signature of a JSON @p payload using an RSA @p publicKey.
 *
 * @note This function expects 'signature' field to be present in the root JSON
 * object. This field is the automatically popped to verify signature on the
 * original data
 *
 * @param publicKey The RSA key pair used for verification
 * @param payload The JSON object containing the data and its signature
 *
 * @return
 * - Success: Boolean equal to true if the signature is valid, false otherwise
 * - Error: String error message (if the verification process failed)
 */
auto verifyPayload(const RsaKeyPair &publicKey, nlohmann::json &payload)
    -> std::expected<bool, std::string>;

} // namespace crypto
