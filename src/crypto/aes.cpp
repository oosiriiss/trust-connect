#include "aes.hpp"
#include "debug_utils.hpp"
#include "logzy/logzy.hpp"
#include "openssl.hpp"
#include <expected>
#include <fcntl.h>
#include <ios>
#include <openssl/evp.h>

namespace crypto {

auto Aes256::generate() -> std::expected<Aes256, std::string> {

  std::expected<Aes256, std::string> aes{Aes256{}};

  logzy::debug("Generating new Aes256 GCM");
  if (auto bytes = crypto::openssl::generateRandomBytes<32>()) {
    aes->rawKey_ = *bytes;
  } else {
    return std::unexpected(std::format(
        "Couldn't create random bytes for AES 256 key. {}", bytes.error()));
  }

  aes->encryptCtx_.reset(EVP_CIPHER_CTX_new());
  aes->decryptCtx_.reset(EVP_CIPHER_CTX_new());

  if (aes->encryptCtx_ == nullptr) {
    return std::unexpected(std::format("Couldn't create encrypting context. {}",
                                       openssl::getError()));
  }

  if (aes->decryptCtx_ == nullptr) {
    return std::unexpected(std::format("Couldn't create decrypting context. {}",
                                       openssl::getError()));
  }
  logzy::debug("Generated.");

  return aes;
}

auto Aes256::fromKey(std::string_view key)
    -> std::expected<Aes256, std::string> {

  if (key.size() != 32) {
    return std::unexpected("Key must have size of 32 bytes");
  }

  logzy::trace("Creating AES 256 GCM from key: {}", key);
  std::expected<Aes256, std::string> aes{Aes256{}};
  std::ranges::copy(key, aes->rawKey_.begin());
  aes->encryptCtx_.reset(EVP_CIPHER_CTX_new());
  aes->decryptCtx_.reset(EVP_CIPHER_CTX_new());

  if (aes->encryptCtx_ == nullptr) {
    return std::unexpected(std::format("Couldn't create encrypting context. {}",
                                       openssl::getError()));
  }

  if (aes->decryptCtx_ == nullptr) {
    return std::unexpected(std::format("Couldn't create decrypting context. {}",
                                       openssl::getError()));
  }

  logzy::trace("Created");

  return aes;
}

auto Aes256::encrypt(std::string_view data) const
    -> std::expected<std::string, std::string> {

  logzy::debug("Encrypting with AES 256 GCM");
  logzy::trace("Encrtypted data size: {}", data.size());

  static_string<12> iv{};
  if (auto randomBytes = openssl::generateRandomBytes<12>()) {
    iv = *randomBytes;
  } else {
    return std::unexpected(
        "Couldn't generate random bytes to initialize initial vector");
  }
  logzy::trace("IV: {}", iv);

  if (EVP_EncryptInit_ex(
          encryptCtx_.get(), EVP_aes_256_gcm(), nullptr,
          reinterpret_cast<const unsigned char *>(rawKey_.data.data()),
          reinterpret_cast<const unsigned char *>(iv.data.data())) <= 0) {
    return std::unexpected(
        std::format("Couldn't initialize context for AES 256 GCM. {}",
                    openssl::getError()));
  }

  std::expected<std::string, std::string> encrypted(
      std::string(IV_SIZE + data.size() + GCM_TAG_SIZE, '\0'));

  logzy::trace("Encrypted content expected size={}", encrypted->size());

  std::ranges::copy(iv, encrypted->begin());

  int writtenContentLength = 0;
  int inputSizeBytes = static_cast<int>(data.size());
  auto *outputStart =
      reinterpret_cast<unsigned char *>(encrypted->data() + IV_SIZE);

  if (EVP_EncryptUpdate(encryptCtx_.get(), outputStart, &writtenContentLength,
                        reinterpret_cast<const unsigned char *>(data.data()),
                        inputSizeBytes) <= 0) {
    return std::unexpected(
        std::format("Couldn't encrypt the data. {}", openssl::getError()));
  }

  int encryptedLength = writtenContentLength + IV_SIZE + GCM_TAG_SIZE;
  auto *tagStart = outputStart + writtenContentLength;

  if (EVP_EncryptFinal_ex(encryptCtx_.get(), tagStart, &writtenContentLength) <=
      0) {
    return std::unexpected(std::format("Couldn't finialize the encryption. {}",
                                       openssl::getError()));
  }
  DEBUG_ASSERT(
      writtenContentLength == 0,
      " AES 256 GCM doesn't write to the buffer, as it doesn't have padding");
  encryptedLength += writtenContentLength;

  logzy::debug(
      "Writing tag. to {}",
      std::string_view{reinterpret_cast<char *>(tagStart), GCM_TAG_SIZE});

  if (EVP_CIPHER_CTX_ctrl(encryptCtx_.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE,
                          tagStart) <= 0) {
    return std::unexpected(
        std::format("Couldnt append tag to the encrypted message. {}",
                    openssl::getError()));
  }
  logzy::debug(
      "Written tag is {}",
      std::string_view{reinterpret_cast<char *>(tagStart), GCM_TAG_SIZE});

  logzy::trace("Encrypted size: Expected size = {}. Real size = {}. Resizing "
               "to match real size.",
               encrypted->size(), encryptedLength);

  if (encryptedLength > encrypted->size()) {
    return std::unexpected(std::format(
        "Encrypted size = {} overflowed the expected buffer with size = {}",
        encryptedLength, encrypted->size()));
  }
  encrypted->resize(encryptedLength);

  return encrypted;
}

auto Aes256::decrypt(std::string_view data) const
    -> std::expected<std::string, std::string> {
  logzy::debug("Decrypting AES 256 GCM");
  logzy::trace("Data size: {}", data.size());

  if (data.size() < IV_SIZE + GCM_TAG_SIZE) {
    return std::unexpected(
        std::format("Not AES256 GCM encrypted data. data.size() should be at "
                    "least '{}' and is '{}'",
                    IV_SIZE + GCM_TAG_SIZE, data.size()));
  }

  const auto *iv = reinterpret_cast<const unsigned char *>(data.data());

  logzy::trace("Initalizing Decrypt context. IV={}", data.substr(0, IV_SIZE));
  if (EVP_DecryptInit_ex(
          decryptCtx_.get(), EVP_aes_256_gcm(), nullptr,
          reinterpret_cast<const unsigned char *>(rawKey_.data.data()),
          iv) <= 0) {
    return std::unexpected(
        std::format("Couldnt initialize decryption context for AES 256 GCM. {}",
                    openssl::getError()));
  }
  const auto *encrypted =
      reinterpret_cast<const unsigned char *>(data.data() + IV_SIZE);
  auto *gcmTag =
      const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(
          data.data() + data.size() - GCM_TAG_SIZE));
  int encryptedLength = static_cast<int>(data.size()) - IV_SIZE - GCM_TAG_SIZE;

  std::expected<std::string, std::string> decrypted{
      std::string(encryptedLength, '\0')};

  logzy::trace("Expected decrypted size = {}", decrypted->size());

  int length = 0;
  auto *decryptedStart = reinterpret_cast<unsigned char *>(decrypted->data());

  if (EVP_DecryptUpdate(decryptCtx_.get(), decryptedStart, &length, encrypted,
                        encryptedLength) <= 0) {
    return std::unexpected(
        std::format("Couldn't decrypt data. {}", openssl::getError()));
  }

  logzy::debug("Calculating gcm tag");
  int decryptedLength = length;
  if (EVP_CIPHER_CTX_ctrl(decryptCtx_.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                          gcmTag) <= 0) {
    return std::unexpected(
        std::format("Couldn't set GCM tag size. {}", openssl::getError()));
  }

  logzy::debug("Verifying gcm tag");

  if (EVP_DecryptFinal_ex(decryptCtx_.get(), decryptedStart, &length) <= 0) {
    return std::unexpected(
        std::format("Decryption failed. {}", openssl::getError()));
  }
  logzy::debug("Tag ok");

  DEBUG_ASSERT(
      length == 0,
      " AES 256 GCM doesn't write to the buffer, as it doesn't have padding");
  decryptedLength += length;

  if (decryptedLength > decrypted->size()) {
    return std::unexpected(std::format(
        "Decrypted size = {} overflowed the expected buffer with size = {}",
        decryptedLength, decrypted->size()));
  }
  decrypted->resize(decryptedLength);

  return decrypted;
}
} // namespace crypto
