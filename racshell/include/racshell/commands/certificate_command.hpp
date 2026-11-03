#pragma once

#include <argparse.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>

#include "include/racshell/command_helper.hpp"
#include "sear/sear.h"

namespace racshell
{

    struct CertificateCommandSpec
    {
        const char *command_name;
        const char *operation;
        const char *success_verb;
        bool add_certificate;
    };

    inline int run_certificate_command(int argc, char *argv[], const CertificateCommandSpec &spec)
    {
        argparse::ArgumentParser program(spec.command_name);

        program.add_argument("owner")
            .help("certificate owner userid");
        program.add_argument("keyring")
            .help("keyring name");
        program.add_argument("keyring-owner")
            .help("keyring owner userid");
        program.add_argument("label")
            .help("certificate label");

        if (spec.add_certificate)
        {
            program.add_argument("certificate-file")
                .help("certificate file path");
            program.add_argument("usage")
                .help("certificate usage");
            program.add_argument("status")
                .help("certificate status");
        }

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
            print_error(std::cerr, "Invalid input, certificate owner userid must be between 1 and 8 characters");
            return 1;
        }

        const std::string keyring = program.get<std::string>("keyring");
        if (keyring.empty() || keyring.length() > 238)
        {
            print_error(std::cerr, "Invalid input, keyring name must be between 1 and 238 characters");
            return 1;
        }

        const std::string keyring_owner = program.get<std::string>("keyring-owner");
        if (keyring_owner.empty() || keyring_owner.length() > 8)
        {
            print_error(std::cerr, "Invalid input, keyring owner userid must be between 1 and 8 characters");
            return 1;
        }

        const std::string label = program.get<std::string>("label");
        if (label.empty())
        {
            print_error(std::cerr, "Invalid input, certificate label must not be empty");
            return 1;
        }

        const bool debug = program.get<bool>("debug");
        const bool json_output = program.get<bool>("json");
        const bool all_json = program.get<bool>("all-json");

        nlohmann::json request = {
            {"operation", spec.operation},
            {"admin_type", "certificate"},
            {"owner", to_racf_identifier_text(owner)},
            {"keyring", to_racf_identifier_text(keyring)},
            {"keyring_owner", to_racf_identifier_text(keyring_owner)},
            {"label", to_racf_identifier_text(label)}};

        if (spec.add_certificate)
        {
            const std::string certificate_file = program.get<std::string>("certificate-file");
            const std::string usage = program.get<std::string>("usage");
            const std::string status = program.get<std::string>("status");
            if (certificate_file.empty() || usage.empty() || status.empty())
            {
                print_error(std::cerr, "Invalid input, certificate file, usage, and status must not be empty");
                return 1;
            }

            request["certificate_file"] = certificate_file;
            request["usage"] = usage;
            request["status"] = status;
        }

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
                {"keyring_owner", keyring_owner},
                {"label", label},
                {"status", spec.success_verb}};
            std::cout << output.dump(2) << "\n";
        }
        else
        {
            print_operation_success(std::cout, spec.operation,
                                    "Certificate " + label + " " + spec.success_verb + " " +
                                        (spec.add_certificate ? "to " : "from ") + "keyring " + keyring +
                                        " owned by " + keyring_owner + " successfully.");
        }
        return 0;
    }

} // namespace racshell