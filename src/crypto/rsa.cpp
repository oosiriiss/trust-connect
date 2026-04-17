#include "rsa.hpp"
#include "crypto/openssl.hpp"
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

auto RsaKeyPair::publicKeyPem() const
    -> std::expected<std::string, std::string> {
  auto bio = openssl::BioPointer{BIO_new(BIO_s_mem()),
                                 openssl::internal::BioDeleter{}};
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
  auto bio = openssl::BioPointer{BIO_new(BIO_s_mem()),
                                 openssl::internal::BioDeleter{}};
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
  constexpr int (*callback)(char *, int, int, void *) = nullptr;
  constexpr void *callbackData = nullptr;

  if (PEM_write_bio_PrivateKey(bio.get(), rawKey.get(), cipherFun, passphrase,
                               passphraseLength, callback, callbackData) == 0) {
    return std::unexpected("Couldn't write PEM from private key: " +
                           openssl::getError());
  }

  BUF_MEM *bufMem = nullptr;
  BIO_get_mem_ptr(bio.get(), &bufMem);
  pem->append(bufMem->data, bufMem->length);
  return pem;
}

} // namespace crypto
