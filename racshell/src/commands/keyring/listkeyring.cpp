#include <argparse.hpp>
#include <iostream>
#include <string>

#include "include/racshell/command_helper.hpp"
#include "sear/sear.h"

namespace
{
    std::string display_value(const nlohmann::json &value)
    {
        return value.is_string() ? value.get<std::string>() : value.dump();
    }

    void print_title(const std::string &title, std::size_t indent = 0)
    {
        std::cout << std::string(indent, ' ') << title << "\n";
    }

    void print_field(const std::string &label, const nlohmann::json &value, std::size_t indent = 2)
    {
        std::cout << std::string(indent, ' ');
        std::cout << label << ": ";
        if (value.is_boolean())
        {
            racshell::print_colored_text(std::cout,
                                         value.get<bool>() ? racshell::terminal_color::green : racshell::terminal_color::red,
                                         value.get<bool>() ? "YES" : "NO");
        }
        else
        {
            racshell::print_colored_text(std::cout, racshell::terminal_color::blue, display_value(value));
        }
        std::cout << "\n";
    }

    void print_certificate_field(const nlohmann::json &certificate,
                                 const char *key,
                                 const char *label)
    {
        const auto value = certificate.find(key);
        if (value != certificate.end() && !value->is_structured() && !value->is_null())
        {
            print_field(label, *value, 4);
        }
    }

    void print_certificate(const nlohmann::json &certificate, std::size_t index)
    {
        const std::string label = certificate.value("label", std::string());
        std::string title = "Certificate " + std::to_string(index + 1);
        if (!label.empty())
        {
            title += " - " + label;
        }
        print_title(title, 2);

        print_certificate_field(certificate, "owner", "Owner");
        print_certificate_field(certificate, "DN", "Subject");
        print_certificate_field(certificate, "issuer", "Issuer");
        print_certificate_field(certificate, "usage", "Usage");
        print_certificate_field(certificate, "status", "Status");
        print_certificate_field(certificate, "default", "Default");
        print_certificate_field(certificate, "privateKey", "Private key");
        print_certificate_field(certificate, "keySize", "Key size");
        print_certificate_field(certificate, "version", "Version");
        print_certificate_field(certificate, "serialNumber", "Serial number");
        print_certificate_field(certificate, "notBefore", "Valid from");
        print_certificate_field(certificate, "notAfter", "Valid until");

        const auto fingerprints = certificate.find("fingerprints");
        if (fingerprints != certificate.end() && fingerprints->is_array() && !fingerprints->empty())
        {
            print_title("Fingerprints", 4);
            for (const auto &fingerprint : *fingerprints)
            {
                if (fingerprint.is_object())
                {
                    for (auto it = fingerprint.begin(); it != fingerprint.end(); ++it)
                    {
                        print_field(it.key(), it.value(), 6);
                    }
                }
            }
        }

        const auto extensions = certificate.find("extensions");
        if (extensions != certificate.end() && extensions->is_array() && !extensions->empty())
        {
            print_title("Extensions", 4);
            for (const auto &extension : *extensions)
            {
                if (!extension.is_object())
                {
                    continue;
                }

                std::string extension_title = extension.value("name", std::string("Extension"));
                if (extension.value("critical", std::string("no")) == "yes")
                {
                    extension_title += " (critical)";
                }
                print_title(extension_title, 6);

                const auto value = extension.find("value");
                if (value != extension.end() && !value->is_structured() && !value->is_null())
                {
                    print_field("Value", *value, 8);
                }

                const auto usages = extension.find("usages");
                if (usages != extension.end() && usages->is_array())
                {
                    for (const auto &usage : *usages)
                    {
                        print_field("Usage", usage, 8);
                    }
                }

                const auto altnames = extension.find("altnames");
                if (altnames != extension.end() && altnames->is_array())
                {
                    for (const auto &altname : *altnames)
                    {
                        if (altname.is_object())
                        {
                            const std::string type = altname.value("type", std::string("Name"));
                            const std::string name = altname.value("name", std::string());
                            print_field(type, name, 8);
                        }
                    }
                }
            }
        }

        const auto signature = certificate.find("signature");
        if (signature != certificate.end() && signature->is_object())
        {
            const auto algorithm = signature->find("algorithm");
            if (algorithm != signature->end())
            {
                print_field("Signature", *algorithm, 4);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    argparse::ArgumentParser program("listkeyring");

    program.add_argument("-o", "--owner")
        .required()
        .help("owner userid");
    program.add_argument("-k", "--keyring")
        .required()
        .help("keyring name");

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

    const std::string owner = program.get<std::string>("owner");
    if (owner.empty() || owner.length() > 8)
    {
        racshell::print_error(std::cerr, "Invalid input, owner userid must be between 1 and 8 characters");
        return 1;
    }

    const std::string keyring = program.get<std::string>("keyring");
    if (keyring.empty() || keyring.length() > 238)
    {
        racshell::print_error(std::cerr, "Invalid input, keyring name must be between 1 and 238 characters");
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
        nlohmann::ordered_json output = {
            {"owner", owner},
            {"keyring", keyring},
            {"details", *keyring_data}};
        std::cout << output.dump(2) << "\n";
    }
    else
    {
        print_title("Keyring");
        print_field("Owner", owner);
        print_field("Name", keyring);

        const auto certificates = keyring_data->find("certificates");
        if (certificates == keyring_data->end() || !certificates->is_array() || certificates->empty())
        {
            print_title("Certificates: none");
        }
        else
        {
            print_title("Certificates (" + std::to_string(certificates->size()) + ")");
            for (std::size_t index = 0; index < certificates->size(); ++index)
            {
                print_certificate((*certificates)[index], index);
            }
        }
    }
    return 0;
}