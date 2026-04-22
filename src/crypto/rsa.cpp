#include "rsa.hpp"
#include "crypto/openssl.hpp"
#include "logzy/logzy.hpp"
#include <expected>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace crypto {

auto RsaKeyPair::generate() -> std::expected<RsaKeyPair, std::string> {

  EVP_PKEY *key = EVP_RSA_gen(RsaKeyPair::KEY_BITS);
  if (key == nullptr) {
    return std::unexpected("Couldn't generate RSA Key pair: " +
                           openssl::getError());
  }

  return std::expected<RsaKeyPair, std::string>{RsaKeyPair{
      .rawKey =
          openssl::RsaKeyPointer{key, openssl::internal::RsaKeyDeleter{}}}};
}

auto RsaKeyPair::fromPublicPem(std::string_view publicPem)
    -> std::expected<RsaKeyPair, std::string> {

  logzy::trace("Creating RSA keypair from public key");
  if (publicPem.empty()) {
    return std::unexpected(std::string("public PEM is empty"));
  }

  auto bio = openssl::BioPointer{
      BIO_new_mem_buf(publicPem.data(), static_cast<int>(publicPem.size()))};

  if (bio == nullptr) {
    return std::unexpected(
        std::string("Couldn't create BIO for the public key PEM"));
  }
  logzy::trace("BIO Created");

  logzy::trace("Reading the public key");
  EVP_PKEY *out = nullptr; // when out is nullptr openssl allocates
                           // memory for the buf and returns it
  constexpr pem_password_cb(*passphraseCallback) = nullptr;
  constexpr void *callbackData = nullptr;
  auto key = openssl::RsaKeyPointer{
      PEM_read_bio_PUBKEY(bio.get(), &out, passphraseCallback, callbackData)};

  if (key == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create RSA keypair from public key PEM:\n {}", publicPem));
  }

  logzy::trace("RSA keypair parsed - only public key");
  return RsaKeyPair{.rawKey = std::move(key)};
}

auto RsaKeyPair::fromPrivatePem(std::string_view privatePem)
    -> std::expected<RsaKeyPair, std::string> {

  logzy::trace("Creating RSA keypair from Private key");
  if (privatePem.empty()) {
    return std::unexpected(std::string("private PEM is empty"));
  }

  auto bio = openssl::BioPointer{
      BIO_new_mem_buf(privatePem.data(), static_cast<int>(privatePem.size()))};

  if (bio == nullptr) {
    return std::unexpected(
        std::string("Couldn't create BIO from the private key PEM"));
  }

  logzy::trace("BIO Created");

  EVP_PKEY *out = nullptr; // when out is nullptr openssl allocates
                           // memory for the buf and returns it
  constexpr pem_password_cb(*passphraseCallback) = nullptr;
  constexpr void *callbackData = nullptr;

  logzy::trace("Reading the private key");
  auto key = openssl::RsaKeyPointer{PEM_read_bio_PrivateKey(
      bio.get(), &out, passphraseCallback, callbackData)};

  if (key == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create RSA keypair from private key PEM:\n {}", privatePem));
  }

  logzy::trace("RSA keypair parsed");
  return RsaKeyPair{.rawKey = std::move(key)};
}

auto RsaKeyPair::sign(std::string_view data) const noexcept
    -> std::expected<std::string, std::string> {

  logzy::debug("Signing data with size: {}", data.size());
  logzy::trace("Signed data: {}", data);

  auto ctx = openssl::MdCtxPointer{EVP_MD_CTX_new()};
  if (ctx == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create message digest context. {}", openssl::getError()));
  }
  logzy::trace("Generated context");

  if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                         rawKey.get()) <= 0) {
    return std::unexpected(std::format(
        "Couldn't initialize digest sign context. {}", openssl::getError()));
  }
  logzy::trace("Initialized digest sign context");

  logzy::trace("Querying for size");
  size_t signLength = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &signLength,
                     reinterpret_cast<const unsigned char *>(data.data()),
                     data.size()) <= 0) {
    return std::unexpected(std::format("Querying for digest size failed. {}",
                                       openssl::getError()));
  }
  logzy::trace("Digest size: {}", signLength);

  std::expected<std::string, std::string> sign{
      std::string(signLength + 5, '\0')};

  if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char *>(sign->data()),
                     &signLength,
                     reinterpret_cast<const unsigned char *>(data.data()),
                     data.size()) <= 0) {
    return std::unexpected(
        std::format("Signing failed. {}", openssl::getError()));
  }

  sign->resize(signLength);
  logzy::debug("Successfully signed");
  return sign;
}

auto RsaKeyPair::verify(std::string_view data,
                        std::string_view signature) const noexcept
    -> std::expected<bool, std::string> {
  logzy::debug("Verifying signature");
  logzy::trace("Signature: '{}'\nData size:\n '{}'", signature, data.size());
  if (rawKey == nullptr) {
    return std::unexpected("EVP_PKEY is null. key was not loaded.");
  }

  auto ctx = openssl::MdCtxPointer{EVP_MD_CTX_new()};
  if (ctx == nullptr) {
    return std::unexpected(std::format(
        "Couldn't create message digest context. {}", openssl::getError()));
  }
  logzy::trace("Generated context");

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                           rawKey.get()) <= 0) {
    return std::unexpected(std::format("Couldn't intialize verification. {}",
                                       openssl::getError()));
  }
  logzy::trace("Initialzied digest context");

  const int result = EVP_DigestVerify(
      ctx.get(), reinterpret_cast<const unsigned char *>(signature.data()),
      signature.size(), reinterpret_cast<const unsigned char *>(data.data()),
      data.size());

  logzy::trace("Verified. result = {}", result);

  if (result < 0) {
    return std::unexpected(std::format("Error occurred during verification. {}",
                                       openssl::getError()));
  }

  if (result == 0) {
    logzy::trace("Verification failed. The signature doesn't match.");
    return false;
  }

  logzy::debug("Verification success");
  return true;
}

auto RsaKeyPair::publicKeyPem() const
    -> std::expected<std::string, std::string> {
  auto bio = openssl::BioPointer{BIO_new(BIO_s_mem())};
  if (bio == nullptr) {
    return std::unexpected("Couldn't create BIO from public key PEM: " +
                           openssl::getError());
  }

  std::expected<std::string, std::string> pem{std::string{}};

  if (PEM_write_bio_PUBKEY(bio.get(), rawKey.get()) == 0) {
    return std::unexpected("Couldn't write PEM from public key: " +
                           openssl::getError());
  }

  BUF_MEM *bufMem = nullptr;
  BIO_get_mem_ptr(bio.get(), &bufMem);

  pem->append(bufMem->data, bufMem->length);

  return pem;
}

auto RsaKeyPair::privateKeyPem() const
    -> std::expected<std::string, std::string> {
  auto bio = openssl::BioPointer{BIO_new(BIO_s_mem())};
  if (bio == nullptr) {
    return std::unexpected("Couldn't create BIO from private key PEM: " +
                           openssl::getError());
  }

  std::expected<std::string, std::string> pem{std::string{}};

  // TODO :: Passphrase or cipher for the privatekey
  // https://docs.openssl.org/1.0.2/man3/pem/#pem-encryption-format

  // Right now there is no private key encryption
  constexpr EVP_CIPHER *cipherFun = nullptr;
  constexpr const unsigned char *passphrase = nullptr;
  constexpr auto passphraseLength = 0;
  constexpr pem_password_cb(*passphraseCallback) = nullptr;
  constexpr void *callbackData = nullptr;

  if (PEM_write_bio_PrivateKey(bio.get(), rawKey.get(), cipherFun, passphrase,
                               passphraseLength, passphraseCallback,
                               callbackData) == 0) {
    return std::unexpected("Couldn't write PEM from private key: " +
                           openssl::getError());
  }

  BUF_MEM *bufMem = nullptr;
  BIO_get_mem_ptr(bio.get(), &bufMem);
  pem->append(bufMem->data, bufMem->length);
  return pem;
}

[[nodiscard]] auto RsaKeyPair::encryptPublic(std::string_view plain) const
    -> std::expected<std::string, std::string> {
  logzy::trace("Encrypting: '{}'", plain);

  auto ctx = openssl::KeyCtxPointer{EVP_PKEY_CTX_new(rawKey.get(), nullptr)};
  if (ctx == nullptr) {
    return std::unexpected(std::string("Couldn't create context to decrypt"));
  }

  if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
    return std::unexpected(
        std::format("Couldnt initialize encryption. {}", openssl::getError()));
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
    return std::unexpected(std::format("Couldnt set padding for encryption. {}",
                                       openssl::getError()));
  }

  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0) {
    return std::unexpected(std::format("Couldn't set padding hash function. {}",
                                       openssl::getError()));
  }

  size_t resultLength = 0;

  if (EVP_PKEY_encrypt(
          ctx.get(), nullptr, &resultLength,
          reinterpret_cast<const unsigned char *>(plain.data()), // NOLINT
          plain.size()) <= 0) {
    return std::unexpected(
        std::format("Encryption size query failed. {}", openssl::getError()));
  }
  // 5 because why not
  std::string buffer(resultLength + 5, '\0');

  if (EVP_PKEY_encrypt(
          ctx.get(),
          reinterpret_cast<unsigned char *>(buffer.data()), // NOLINT
          &resultLength,
          reinterpret_cast<const unsigned char *>(plain.data()), // NOLINT
          plain.size()) <= 0) {
    return std::unexpected(
        std::format("Encryption failed. {}", openssl::getError()));
  }

  buffer.resize(resultLength);
  logzy::trace("Encrypted: '{}'", buffer);

  return buffer;
}

[[nodiscard]] auto RsaKeyPair::decryptPrivate(std::string_view cipher) const
    -> std::expected<std::string, std::string> {
  logzy::trace("Decrypting: '{}'", cipher);

  auto ctx = openssl::KeyCtxPointer{EVP_PKEY_CTX_new(rawKey.get(), nullptr)};
  if (ctx == nullptr) {
    return std::unexpected(std::string("Couldn't create context to decrypt"));
  }

  if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
    return std::unexpected(
        std::format("Couldnt initialize encryption. {}", openssl::getError()));
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
    return std::unexpected(std::format("Couldnt set padding for encryption. {}",
                                       openssl::getError()));
  }

  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0) {
    return std::unexpected(std::format("Couldn't set padding hash function. {}",
                                       openssl::getError()));
  }

  size_t resultLength = 0;

  if (EVP_PKEY_decrypt(
          ctx.get(), nullptr, &resultLength,
          reinterpret_cast<const unsigned char *>(cipher.data()), // NOLINT
          cipher.size()) <= 0) {
    return std::unexpected(
        std::format("Decryption size query failed. {}", openssl::getError()));
  }
  // 5 because why not
  std::string buffer(resultLength + 5, '\0');

  if (EVP_PKEY_decrypt(
          ctx.get(),
          reinterpret_cast<unsigned char *>(buffer.data()), // NOLINT
          &resultLength,
          reinterpret_cast<const unsigned char *>(cipher.data()), // NOLINT
          cipher.size()) <= 0) {
    return std::unexpected(
        std::format("Decryption failed. {}", openssl::getError()));
  }
  buffer.resize(resultLength);
  logzy::trace("Decrypted: '{}'", buffer);

  return buffer;
}

} // namespace crypto
