#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "logzy/logzy.hpp"
#include <print>

namespace {

enum class OptionKey {
  Port,
  Help,
};

auto getOptions() {
  cppli::OptionContainer<OptionKey> options;

  options.addOption(
      OptionKey::Port,
      cppli::Option{.firstName = "-p",
                    .secondName = "--port",
                    .description =
                        "Specifies the port at which the server will listen on",
                    .needsValue = true});
  options.addOption(OptionKey::Help,
                    cppli::Option{.firstName = "-h",
                                  .secondName = "--help",
                                  .description = "Displays the help message",
                                  .needsValue = false});

  return options;
}

auto parseCommandlineArgs(std::uint16_t &ctx, int argc,
                          char const *const *const argv) -> bool {

  cppli::OptionContainer<OptionKey> options = getOptions();
  cppli::ParseResult<OptionKey> result;
  try {
    result = cppli::parseArguments(argc, argv, options);
  } catch (const std::exception &exc) {
    std::println("Couldn't parse arguments: {}", exc.what());
    return true;
  }

  // Help terminates
  if (result.options.contains(OptionKey::Help)) {
    std::println("{}", cppli::createHelp(options, "ttp"));
    return true;
  }

  if (auto port = result.options.find(OptionKey::Port);
      port != result.options.end()) {
    ctx = std::stoi(std::string(port->second.value.value()));
  }

  return false;
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  std::uint16_t port = network::DEFAULT_SERVER_PORT;

  if (parseCommandlineArgs(port, argc, argv)) {
    return EXIT_SUCCESS;
  }

  logzy::info("Listening on port: {}", port);

  return 0;
}
