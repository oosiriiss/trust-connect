#include "x509.hpp"
#include "crypto/openssl.hpp"
#include "crypto/rsa.hpp"
#include "debug_utils.hpp"
#include "logzy/logzy.hpp"

#include <expected>
#include <fcntl.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace crypto {

auto X509Certificate::createSelfSignedCA(std::string_view name,
                                         const RsaKeyPair &caKey) noexcept
    -> std::expected<X509Certificate, std::string> {
  logzy::debug("Creating Self signed CA for '{}'", name);

  auto x509 = openssl::X509Pointer{X509_new()};
  if (x509 == nullptr) {
    return std::unexpected(std::format("Couldn't create new certificate. {}",
                                       openssl::getError()));
  }

  logzy::trace("Setting version to 3");
  if (X509_set_version(x509.get(), X509_VERSION_3) != 1) {
    return std::unexpected(std::format(
        "Couldn't set version for the certificate {}", openssl::getError()));
  }

  logzy::trace("Setting version to: {}", X509SerialNumbercounter);
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()),
                   X509SerialNumbercounter++);

  if (X509_gmtime_adj(X509_get_notBefore(x509.get()), 0) == nullptr) {
    return std::unexpected(std::format(
        "Couldn't set notBefore for the certificate {}", openssl::getError()));
  }

  constexpr long secondsInAYear = 365L * 24 * 60 * 60; // NOLINT
  logzy::trace("Expiration date in: '{}' seconds", secondsInAYear);
  if (X509_gmtime_adj(X509_get_notAfter(x509.get()), secondsInAYear) ==
      nullptr) {
    return std::unexpected(std::format(
        "Couldn't set notAfter for the certificate {}", openssl::getError()));
  }

  logzy::trace("Setting public key");
  if (X509_set_pubkey(x509.get(), caKey.rawKey.get()) != 1) {
    return std::unexpected(std::format(
        "Couldn't set public key for the certificate {}", openssl::getError()));
  }

  logzy::debug("Setting name fileds");
  X509_NAME *x509Name = X509_get_subject_name(x509.get());
  DEBUG_ASSERT(x509Name != nullptr);

  // Openssly will automatically calculate the length if we do not pass it
  constexpr int dataBytesLength = -1;
  // Position to add to (-1 == append at the end)
  constexpr int position = -1;
  // New attribute, do not join it with the previous one
  constexpr int set = 0;
  if (X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC,
                                 (unsigned char *)"PL", // NOLINT
                                 dataBytesLength, position, set) != 1) {
    return std::unexpected(std::format(
        "Couldn't set 'C' Entry for the certitcate. {}", openssl::getError()));
  }
  if (X509_NAME_add_entry_by_txt(x509Name, "O", MBSTRING_ASC,
                                 (unsigned char *)"oosiriiss", // NOLINT
                                 dataBytesLength, position, set) != 1) {
    return std::unexpected(std::format(
        "Couldn't set 'O' Entry for the certitcate. {}", openssl::getError()));
  }
  if (X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC,
                                 (unsigned char *)name.data(), // NOLINT
                                 static_cast<int>(name.size()), position,
                                 set) != 1) {

    return std::unexpected(std::format(
        "Couldn't set 'CN' Entry for the certitcate. {}", openssl::getError()));
  }

  if (X509_set_issuer_name(x509.get(), x509Name) != 1) {
    return std::unexpected(
        std::format("Setting issuer name failed. {}", openssl::getError()));
  }

  logzy::trace("signing the certificate");
  if (X509_sign(x509.get(), caKey.rawKey.get(), EVP_sha256()) == 0) {
    return std::unexpected(
        std::format("Signing the certificate failed. {}", openssl::getError()));
  }

  logzy::debug("Certificate successfully created.");

  return std::expected<X509Certificate, std::string>(
      X509Certificate{.x509 = std::move(x509)});
}

auto X509Certificate::getRawCertificate() const noexcept
    -> openssl::internal::X509 * {
  if (x509 == nullptr) {
    logzy::warn("Returning null certificate.");
  }

  return x509.get();
}

[[nodiscard]] auto
X509Certificate::issue(const RsaKeyPair &subjectKey,
                       std::string_view subjectName,
                       const RsaKeyPair &caKey) const noexcept

    -> std::expected<X509Certificate, std::string> {

  constexpr size_t maxCommonNameLength = 64;

  if (subjectName.size() > maxCommonNameLength) {
    logzy::warn("maxCommonNameLength='{}' is longer than max CA length={}. "
                "Truncating it to {}",
                subjectName, maxCommonNameLength, maxCommonNameLength);
    subjectName = subjectName.substr(0, maxCommonNameLength);
  }

  logzy::debug("Issueing a certificate for {}", subjectName);
  if (x509 == nullptr) {
    return std::unexpected(
        "Trying to issue with an uninitialized X509Certificate");
  }

  auto x509 = openssl::X509Pointer{X509_new()};
  if (x509 == nullptr) {
    return std::unexpected(std::format("Couldn't create new certificate. {}",
                                       openssl::getError()));
  }

  logzy::trace("Setting version to 3");
  if (X509_set_version(x509.get(), X509_VERSION_3) != 1) {
    return std::unexpected(
        std::format("Couldn't set version for the issued certificate {}",
                    openssl::getError()));
  }

  logzy::trace("Setting issued certificate version to: {}",
               X509SerialNumbercounter);

  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()),
                   X509SerialNumbercounter++);

  if (X509_gmtime_adj(X509_get_notBefore(x509.get()), 0) == nullptr) {
    return std::unexpected(
        std::format("Couldn't set notBefore for the issued certificate {}",
                    openssl::getError()));
  }

  constexpr long secondsInAYear = 365L * 24 * 60 * 60; // NOLINT
  logzy::trace("issued certificate expiration date in: '{}' seconds",
               secondsInAYear);
  if (X509_gmtime_adj(X509_get_notAfter(x509.get()), secondsInAYear) ==
      nullptr) {
    return std::unexpected(
        std::format("Couldn't set notAfter for the issued certificate {}",
                    openssl::getError()));
  }

  logzy::trace("Setting public key");
  if (X509_set_pubkey(x509.get(), subjectKey.rawKey.get()) != 1) {
    return std::unexpected(
        std::format("Couldn't set public key for the issued certificate {}",
                    openssl::getError()));
  }

  logzy::debug("Setting name fileds for issued certificate");
  X509_NAME *x509Name = X509_get_subject_name(x509.get());
  DEBUG_ASSERT(x509Name != nullptr);

  // Openssly will automatically calculate the length if we do not pass it
  constexpr int dataBytesLength = -1;
  // Position to add to (-1 == append at the end)
  constexpr int position = -1;
  // New attribute, do not join it with the previous one
  constexpr int set = 0;
  if (X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC,
                                 (unsigned char *)"PL", // NOLINT
                                 dataBytesLength, position, set) != 1) {
    return std::unexpected(
        std::format("Couldn't set 'C' Entry for the issued certitcate. {}",
                    openssl::getError()));
  }
  if (X509_NAME_add_entry_by_txt(x509Name, "O", MBSTRING_ASC,
                                 (unsigned char *)"oosiriiss", // NOLINT
                                 dataBytesLength, position, set) != 1) {
    return std::unexpected(
        std::format("Couldn't set 'O' Entry for the issued certitcate. {}",
                    openssl::getError()));
  }

  logzy::trace("Setting CN='{}'", subjectName);
  if (X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC,
                                 (unsigned char *)subjectName.data(), // NOLINT
                                 static_cast<int>(subjectName.size()), position,
                                 set) != 1) {

    return std::unexpected(
        std::format("Couldn't set 'CN' Entry for the issued certitcate. {}",
                    openssl::getError()));
  }

  if (X509_set_issuer_name(x509.get(), x509Name) != 1) {
    return std::unexpected(
        std::format("Setting issuer name failed. {}", openssl::getError()));
  }

  logzy::trace("signing the certificate");
  if (X509_sign(x509.get(), caKey.rawKey.get(), EVP_sha256()) == 0) {
    return std::unexpected(
        std::format("Signing the certificate failed. {}", openssl::getError()));
  }

  logzy::debug("Certificate successfully created.");

  return std::expected<X509Certificate, std::string>(
      X509Certificate{.x509 = std::move(x509)});
}

auto X509Certificate::toPem() const -> std::expected<std::string, std::string> {

  logzy::trace("Wiriting certificate to PEM");

  auto bio = openssl::BioPointer{BIO_new(BIO_s_mem())};
  if (bio == nullptr) {
    return std::unexpected(
        std::format("Couldn't create BIO. {}", openssl::getError()));
  }
  logzy::trace("BIO created.");

  if (PEM_write_bio_X509(bio.get(), x509.get()) != 1) {
    return std::unexpected(
        std::format("Couldn't write to BIO. {}", openssl::getError()));
  }
  logzy::trace("Certificate written to memory.");

  BUF_MEM *bufMem = nullptr;
  if (BIO_get_mem_ptr(bio.get(), &bufMem) != 1 || bufMem == nullptr) {
    return std::unexpected(std::format(
        "Couldn't obtain buffer memory pointer. {}", openssl::getError()));
  }

  logzy::trace("Success writing");

  return std::expected<std::string, std::string>(
      std::string(bufMem->data, bufMem->length));
}
auto X509Certificate::fromPem(std::string_view pem) noexcept
    -> std::expected<X509Certificate, std::string> {

  auto bio = openssl::BioPointer{
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
  if (bio == nullptr) {
    return std::unexpected(std::format("Couldnt create ne memory buffer. {}",
                                       openssl::getError()));
  }

  std::expected<X509Certificate, std::string> x509{X509Certificate{}};

  X509 *returnValue =
      nullptr; // We use the function return value isntead of this
  constexpr pem_password_cb(*passphraseCb) = nullptr;
  constexpr void *callbackData = nullptr;
  x509->x509.reset(
      PEM_read_bio_X509(bio.get(), &returnValue, passphraseCb, callbackData));
  if (returnValue == nullptr) {
    return std::unexpected(
        std::format("Couldn't read X509 from BIO. {}", openssl::getError()));
  }

  return x509;
}

[[nodiscard]] auto
X509Certificate::verify(const X509Certificate &toVerify) const
    -> std::expected<bool, std::string> {

  auto caKey = openssl::RsaKeyPointer{X509_get_pubkey(x509.get())};
  if (caKey == nullptr) {
    return std::unexpected(
        std::format("Couldn't extract CA key from own certificate. {}",
                    openssl::getError()));
  }

  const int result = X509_verify(toVerify.x509.get(), caKey.get());

  if (result < 0) {
    return std::unexpected(
        std::format("Verification error. {}", openssl::getError()));
  }

  return result == 1;
}

auto X509Certificate::getCommonName() const
    -> std::expected<std::string, std::string> {

  if (x509 == nullptr) {
    return std::unexpected("Trying to use uninitialized certificate.");
  }

  X509_NAME *subject = X509_get_subject_name(x509.get());
  if (subject == nullptr) {
    return std::unexpected(
        std::format("Couldn'[t get name for the current certificate. {}",
                    openssl::getError()));
  }

  std::string buffer(256, '\0');

  int writtenLength = X509_NAME_get_text_by_NID(
      subject, NID_commonName, buffer.data(), static_cast<int>(buffer.size()));

  if (writtenLength < 0) {
    return std::unexpected("CN not found.");
  }

  buffer.resize(writtenLength);
  return buffer;
}

auto X509Certificate::getCommonNameSafe() const -> std::string {
  return getCommonName().value_or("Unknown");
}

auto X509Certificate::getSerialNumberHex() const
    -> std::expected<std::string, std::string> {

  // TODO :: This method would get more compilcated if correct BINNUM's were
  // used for certificate's serial numbers

  const ASN1_INTEGER *serial = X509_get0_serialNumber(x509.get());

  if (serial == nullptr) {
    return std::unexpected(std::format("Couldn't get x509's seria number. {}",
                                       openssl::getError()));
  }

  return std::expected<std::string, std::string>(
      std::string(reinterpret_cast<char *>(serial->data), serial->length));
}

} // namespace crypto
