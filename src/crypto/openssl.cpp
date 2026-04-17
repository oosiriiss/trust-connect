#include "openssl.hpp"
#include <openssl/err.h>
#include <openssl/rand.h>

#include <array>
#include <string_view>
namespace crypto::openssl {
auto getError() -> std::string {

  std::string error{"Unknown OpenSSL Error"};

  unsigned long errorCode = -1; // NOLINT google-runtime-in
  std::array<char, 512> buffer{};

  while ((errorCode = ERR_get_error()) != 0) {
    ERR_error_string_n(errorCode, buffer.data(), buffer.size());

    error += std::string_view{buffer.begin(), buffer.end()};
    error += '\n';
  }

  return error;
}

template <std::size_t Bytes>
[[nodiscard]] auto generateRandomBytes() noexcept
    -> std::expected<static_string<Bytes>, std::string> {

  std::expected<static_string<Bytes>, std::string> output{
      static_string<Bytes>{}};

  if (RAND_bytes(
          reinterpret_cast<unsigned char *>(output->data.data()), // NOLINT
          Bytes) == 0) {
    return std::unexpected(std::format("RAND_bytes failed: {}", getError()));
  }
  return output;
}

// Explicit instantiations
template auto generateRandomBytes<16>()
    -> std::expected<static_string<16>, std::string>;
template auto generateRandomBytes<32>()
    -> std::expected<static_string<32>, std::string>;
template auto generateRandomBytes<64>()
    -> std::expected<static_string<64>, std::string>;

} // namespace crypto::openssl
