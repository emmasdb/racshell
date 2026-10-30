#pragma once

#include <argparse.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>

#include "include/racshell/command_helper.hpp"
#include "sear/sear.h"

namespace racshell
{

    struct KeyringCommandSpec
    {
        const char *command_name;
        const char *operation;
        const char *success_verb;
    };

    inline int run_keyring_command(int argc, char *argv[], const KeyringCommandSpec &spec)
    {
        argparse::ArgumentParser program(spec.command_name);

        program.add_argument("owner")
            .help("owner userid");
        program.add_argument("keyring")
            .help("keyring name");

        add_no_color_argument(program);
        add_toggle_argument(program, "-d", "--debug", "debug sear request and response");
        add_toggle_argument(program, "-j", "--json", "output as JSON");
        add_toggle_argument(program, "-a", "--all-json", "output full raw SEAR JSON response");

        try
        {
            program.parse_args(argc, argv);
        }
        catch (const std::exception &err)
        {
            print_error(std::cerr, err.what());
            std::cerr << program;
            return 1;
        }

        set_color_output_enabled(!program.get<bool>("no-color"));

        const std::string owner = program.get<std::string>("owner");
        if (owner.empty() || owner.length() > 8)
        {
            print_error(std::cerr, "Invalid input, owner userid must be between 1 and 8 characters");
            return 1;
        }

        const std::string keyring = program.get<std::string>("keyring");
        if (keyring.empty() || keyring.length() > 238)
        {
            print_error(std::cerr, "Invalid input, keyring name must be between 1 and 238 characters");
            return 1;
        }

        const std::string request_keyring = to_racf_identifier_text(keyring);
        const std::string request_owner = to_racf_identifier_text(owner);
        const bool debug = program.get<bool>("debug");
        const bool json_output = program.get<bool>("json");
        const bool all_json = program.get<bool>("all-json");

        const nlohmann::json request = {
            {"operation", spec.operation},
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

        const SearOperationInfo op_info = validate_sear_operation_result(result->result_json);
        if (!op_info.success)
        {
            print_error(std::cerr, op_info.error_message);
            print_sear_errors(op_info.response, std::cerr);
            return 1;
        }

        if (json_output)
        {
            nlohmann::ordered_json output = {
                {"owner", owner},
                {"keyring", keyring},
                {"status", spec.success_verb}};
            std::cout << output.dump(2) << "\n";
        }
        else
        {
            print_operation_success(std::cout, spec.operation,
                                    "Owner " + owner + " keyring " + keyring + " " + spec.success_verb + " successfully.");
        }
        return 0;
    }

} // namespace racshell