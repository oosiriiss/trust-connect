#include "rsa.hpp"
#include "crypto/openssl.hpp"
#include "logzy/logzy.hpp"
#include <expected>
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

  auto ctx = openssl::CtxPointer{EVP_PKEY_CTX_new(rawKey.get(), nullptr)};
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

  auto ctx = openssl::CtxPointer{EVP_PKEY_CTX_new(rawKey.get(), nullptr)};
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
