#pragma once

#include <argparse.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <iostream>
#include <string>
#include <string_view>

#include "include/racshell/command_helper.hpp"
#include "sear/sear.h"

namespace racshell
{

    struct CertificateReturnCodeDescription
    {
        int saf_rc;
        int racf_rc;
        int reason;
        std::string_view description;
    };

    inline constexpr std::array<CertificateReturnCodeDescription, 10> certificate_common_return_codes = {{
        {8, 8, 4, "R_datalib parameter list error."},
        {8, 8, 8, "Not authorized to use the requested R_datalib service."},
        {8, 8, 12, "An internal error caused recovery to get control."},
        {8, 8, 16, "Unable to establish a recovery environment."},
        {8, 8, 20, "The requested function code is not defined."},
        {8, 8, 24, "The parameter-list version is not supported."},
        {8, 8, 28, "The keyring name or RACF user ID is invalid."},
        {8, 8, 72, "The caller is not in task mode."},
        {8, 8, 92, "An internal R_datalib error occurred."},
        {8, 8, 96, "The link-library concatenation contains a non-APF-authorized library."},
    }};

    inline constexpr std::array<CertificateReturnCodeDescription, 18> certificate_data_put_return_codes = {{
        {4, 4, 0, "The certificate was added with NOTRUST status."},
        {4, 4, 4, "The certificate was added; refresh the DIGTCERT class to reflect the update."},
        {4, 4, 8, "The certificate already exists in RACF; the requested label was ignored."},
        {4, 4, 12, "The certificate already exists in RACF; the label was ignored and its status is NOTRUST."},
        {4, 4, 16, "The certificate already exists in RACF; the label was ignored and DIGTCERT needs refresh."},
        {8, 8, 32, "Invalid certificate length or pointer, or the label area is too small."},
        {8, 8, 36, "Unable to decode the certificate."},
        {8, 8, 40, "The private key is not DER-encoded or is not a supported key label format."},
        {8, 8, 44, "The private key encoding, algorithm, or key size is not supported."},
        {8, 8, 48, "The specified private key does not match the existing private key."},
        {8, 8, 52, "The specified key label could not be found."},
        {8, 8, 56, "ICSF returned an error while looking up the key label."},
        {8, 8, 60, "Not authorized to access the ICSF key entry."},
        {8, 8, 64, "The specified certificate label already exists in RACF."},
        {8, 8, 68, "The certificate owner user ID does not exist in RACF."},
        {8, 8, 76, "The certificate cannot be installed."},
        {8, 8, 80, "The certificate exists under a different user ID."},
        {8, 8, 84, "The keyring profile could not be found."},
    }};

    inline constexpr std::array<CertificateReturnCodeDescription, 10> certificate_data_remove_return_codes = {{
        {4, 4, 0, "The certificate was removed from the keyring but remains in RACF because it is connected to other keyrings."},
        {4, 4, 4, "The certificate was removed from the keyring but could not be deleted from RACF due to an unexpected error."},
        {4, 4, 8, "The certificate was removed from the keyring but could not be deleted from RACF due to insufficient authority."},
        {4, 4, 12, "The certificate was removed; refresh the DIGTCERT class to reflect the update."},
        {4, 4, 16, "The certificate was removed from the keyring but remains in RACF because it was used to generate a request."},
        {8, 8, 32, "Invalid label length, label pointer, or certificate owner user ID."},
        {8, 8, 36, "Cannot find a certificate with the specified label and owner ID."},
        {8, 8, 40, "The keyring profile could not be found."},
        {8, 8, 44, "Cannot delete the certificate from RACF because it is connected to other keyrings."},
        {8, 8, 48, "Cannot delete the certificate because it was used to generate a request or its private key is unavailable."},
    }};

    template <std::size_t N>
    inline std::string_view find_certificate_return_code_description(
        const std::array<CertificateReturnCodeDescription, N> &table,
        const SearReturnCodes &codes)
    {
        for (const auto &entry : table)
        {
            if (entry.saf_rc == codes.saf_rc && entry.racf_rc == codes.racf_rc &&
                entry.reason == codes.racf_reason)
            {
                return entry.description;
            }
        }
        return {};
    }

    inline std::string_view certificate_return_code_description(const SearReturnCodes &codes,
                                                                bool add_certificate)
    {
        const std::string_view operation_description = add_certificate
            ? find_certificate_return_code_description(certificate_data_put_return_codes, codes)
            : find_certificate_return_code_description(certificate_data_remove_return_codes, codes);
        if (!operation_description.empty())
        {
            return operation_description;
        }
        return find_certificate_return_code_description(certificate_common_return_codes, codes);
    }

    inline void print_certificate_return_code_description(const nlohmann::json &response,
                                                          bool add_certificate,
                                                          std::ostream &output,
                                                          bool warning)
    {
        const SearReturnCodes codes = extract_sear_return_codes(response);
        const std::string_view description = certificate_return_code_description(codes, add_certificate);
        if (description.empty())
        {
            return;
        }

        if (warning)
        {
            print_colored_text(output, terminal_color::yellow, "RACF Warning") << ": ";
        }
        else
        {
            output << "  RACF detail: ";
        }
        output << description << "\n";
    }

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

        program.add_argument("-o", "--owner")
            .required()
            .help("certificate owner userid");
        program.add_argument("-k", "--keyring")
            .required()
            .help("keyring name");
        program.add_argument("--keyring-owner")
            .required()
            .help("keyring owner userid");
        program.add_argument("-l", "--label")
            .required()
            .help("certificate label");

        if (spec.add_certificate)
        {
            program.add_argument("-f", "--certificate-file")
                .required()
                .help("certificate file path");
            program.add_argument("-u", "--usage")
                .required()
                .help("certificate usage");
            program.add_argument("-s", "--status")
                .required()
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
        if (debug)
        {
            std::cerr << "SEAR request JSON:\n" << request_json << "\n";
        }
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
            print_certificate_return_code_description(op_info.response, spec.add_certificate, std::cerr, false);
            return 1;
        }

        const SearReturnCodes return_codes = extract_sear_return_codes(op_info.response);
        if (return_codes.saf_rc == 4 || return_codes.racf_rc == 4)
        {
            print_certificate_return_code_description(op_info.response, spec.add_certificate, std::cerr, true);
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