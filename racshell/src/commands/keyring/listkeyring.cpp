#include <argparse.hpp>
#include <iostream>
#include <string>

#include "include/racshell/command_helper.hpp"
#include "sear/sear.h"

int main(int argc, char *argv[])
{
    argparse::ArgumentParser program("listkeyring");

    program.add_argument("keyring")
        .help("keyring name");
    program.add_argument("owner")
        .help("owner userid");

    racshell::add_no_color_argument(program);
    racshell::add_toggle_argument(program, "-d", "--debug", "debug sear request and response");
    racshell::add_toggle_argument(program, "-j", "--json", "output as JSON");
    racshell::add_toggle_argument(program, "-a", "--all-json", "output full raw SEAR JSON response");

    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::exception &err)
    {
        racshell::print_error(std::cerr, err.what());
        std::cerr << program;
        return 1;
    }

    racshell::set_color_output_enabled(!program.get<bool>("no-color"));

    const std::string keyring = program.get<std::string>("keyring");
    if (keyring.empty() || keyring.length() > 238)
    {
        racshell::print_error(std::cerr, "Invalid input, keyring name must be between 1 and 238 characters");
        return 1;
    }

    const std::string owner = program.get<std::string>("owner");
    if (owner.empty() || owner.length() > 8)
    {
        racshell::print_error(std::cerr, "Invalid input, owner userid must be between 1 and 8 characters");
        return 1;
    }

    const std::string request_keyring = racshell::to_racf_identifier_text(keyring);
    const std::string request_owner = racshell::to_racf_identifier_text(owner);
    const bool debug = program.get<bool>("debug");
    const bool json_output = program.get<bool>("json");
    const bool all_json = program.get<bool>("all-json");

    const nlohmann::json request = {
        {"operation", "extract"},
        {"admin_type", "keyring"},
        {"keyring", request_keyring},
        {"owner", request_owner}};

    const std::string request_json = request.dump();
    sear_result_t *result = sear(request_json.c_str(), request_json.length(), debug);

    if (all_json)
    {
        std::cout << result->result_json << "\n";
        return 0;
    }

    const racshell::SearOperationInfo op_info = racshell::validate_sear_operation_result(result->result_json);
    if (!op_info.success)
    {
        racshell::print_error(std::cerr, op_info.error_message);
        racshell::print_sear_errors(op_info.response, std::cerr);
        return 1;
    }

    const auto keyring_data = op_info.response.find("keyring");
    if (keyring_data == op_info.response.end() || !keyring_data->is_object())
    {
        racshell::print_error(std::cerr, "Keyring not found or missing keyring data");
        return 1;
    }

    if (json_output)
    {
        nlohmann::json output = {
            {"keyring", keyring},
            {"owner", owner},
            {"details", *keyring_data}};
        std::cout << output.dump(2) << "\n";
    }
    else
    {
        std::cout << "Keyring " << keyring << " owned by " << owner << ":\n";
        std::cout << keyring_data->dump(2) << "\n";
    }
    return 0;
}