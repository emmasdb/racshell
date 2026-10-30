#include "racshell/output_formatter.hpp"
#include "include/racshell/command_helper.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>
#include <string_view>

namespace
{

    std::string format_security_key(std::string key)
    {
        const std::string::size_type separator_pos = key.find_last_of(':');
        if (separator_pos != std::string::npos)
        {
            key = key.substr(separator_pos + 1);
        }

        for (char &c : key)
        {
            if (c == '_')
            {
                c = ' ';
            }
        }

        if (!key.empty())
        {
            key[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(key[0])));
        }

        return key;
    }

    void append_boolean(std::stringstream &ss, bool value)
    {
        racshell::print_colored_text(ss,
                                     value ? racshell::terminal_color::green : racshell::terminal_color::red,
                                     value ? "YES" : "NO");
    }

    template <typename T>
    void append_styled_value(std::stringstream &ss, const T &value)
    {
        std::stringstream value_stream;
        value_stream << value;
        racshell::print_colored_text(ss, racshell::terminal_color::blue, value_stream.str());
    }

    void append_styled_value(std::stringstream &ss, const nlohmann::json &value)
    {
        if (value.is_boolean())
        {
            append_boolean(ss, value.get<bool>());
        }
        else if (value.is_string())
        {
            append_styled_value(ss, value.get<std::string>());
        }
        else
        {
            append_styled_value(ss, value.dump());
        }
    }

    template <typename T>
    void append_field(std::stringstream &ss, std::string_view label, const T &value)
    {
        ss << label;
        append_styled_value(ss, value);
        ss << "\n";
    }

    void append_json_value(std::stringstream &ss, const nlohmann::json &value)
    {
        append_styled_value(ss, value);
    }

    void append_comparison_value_text(std::stringstream &ss, const nlohmann::json &value)
    {
        if (value.is_boolean())
        {
            append_boolean(ss, value.get<bool>());
        }
        else
        {
            append_styled_value(ss, racshell::value_to_text(value));
        }
    }

    void append_segment_label(std::stringstream &ss, std::string_view segment)
    {
        ss << "\n";
        racshell::print_colored_text(ss, racshell::terminal_color::cyan, segment);
        ss << ":";
    }

    void append_segment_heading(std::stringstream &ss, std::string_view segment)
    {
        append_segment_label(ss, segment);
        ss << "\n";
    }

    void append_csdata(std::stringstream &ss, const nlohmann::json &csdata)
    {
        if (!csdata.is_null() && !csdata.empty())
        {
            append_segment_heading(ss, "CSDATA");
            for (auto it = csdata.begin(); it != csdata.end(); ++it)
            {
                ss << "  " << format_security_key(it.key()) << ": ";
                append_json_value(ss, it.value());
                ss << "\n";
            }
        }
    }

    void append_access_list(std::stringstream &ss, const std::vector<AccessEntry> &access_list)
    {
        if (!access_list.empty())
        {
            ss << "Access List:\n";
            for (const auto &entry : access_list)
            {
                ss << "  ";
                append_styled_value(ss, entry.access_type);
                if (!entry.access_id.empty())
                {
                    ss << " (";
                    append_styled_value(ss, entry.access_id);
                    ss << ")";
                }
                ss << "\n";
            }
        }
    }

    void print_user_list(std::stringstream &ss, const std::string &heading, const nlohmann::json &users)
    {
        ss << heading << "\n";
        for (const auto &user : users)
        {
            ss << "    ";
            append_styled_value(ss, user.value("userid", ""));
            ss << " (";
            append_styled_value(ss, user.value("authority", ""));
            ss << ")\n";
        }
    }

    void print_group_list(std::stringstream &ss, const std::string &heading, const nlohmann::json &groups)
    {
        ss << heading << "\n";
        for (const auto &group : groups)
        {
            ss << "    ";
            append_styled_value(ss, racshell::value_to_text(group));
            ss << "\n";
        }
    }

    
    void append_comparison_value(std::stringstream &ss,
                                 const std::string &left_groupid,
                                 const std::string &right_groupid,
                                 const nlohmann::json &difference,
                                 const std::string &label)
    {
        ss << "  ";
        const bool segment_label = label == "tso" || label == "kerberos" ||
                       label == "cics" || label == "omvs" || label == "csdata";
        racshell::colorize(ss, segment_label ? racshell::terminal_color::cyan : racshell::terminal_color::gray) << label;
        racshell::reset_color(ss) << ": ";

        racshell::colorize(ss, racshell::terminal_color::magenta) << left_groupid;
        racshell::reset_color(ss) << "='";
        append_comparison_value_text(ss, difference.contains("left") ? difference["left"] : nlohmann::json());
        ss << "', ";

        racshell::colorize(ss, racshell::terminal_color::cyan) << right_groupid;
        racshell::reset_color(ss) << "='";
        append_comparison_value_text(ss, difference.contains("right") ? difference["right"] : nlohmann::json());
        ss << "'\n";
    }

} // namespace

std::string TextFormatter::format(const UserData &user)
{
    std::stringstream ss;

    append_field(ss, "User: ", user.userid);
    append_field(ss, "Name: ", user.name);
    append_field(ss, "Installation data: ", user.installation_data);
    append_field(ss, "Owner: ", user.owner);
    append_field(ss, "Default group: ", user.default_group);
    append_field(ss, "Created: ", user.created_date);
    append_field(ss, "Last access date: ", user.last_access_date);
    append_field(ss, "Last access time: ", user.last_access_time);
    ss << "Protected: ";
    append_boolean(ss, user.protected_user);
    ss << "\n";
    ss << "Restricted: ";
    append_boolean(ss, user.restrict_global_access_checking);
    ss << "\n";
    ss << "Special: ";
    append_boolean(ss, user.special);
    ss << "\n";
    ss << "Operations: ";
    append_boolean(ss, user.operations);
    ss << "\n";
    ss << "Auditor: ";
    append_boolean(ss, user.auditor);
    ss << "\n";
    ss << "Read-only auditor: ";
    append_boolean(ss, user.read_only_auditor);
    ss << "\n";
    ss << "Revoked: ";
    append_boolean(ss, user.revoked);
    ss << "\n";
    if (!user.revoke_date.empty())
    {
        append_field(ss, "Revoke date: ", user.revoke_date);
    }
    ss << "Password expired: ";
    append_boolean(ss, user.password_expired);
    ss << "\n";
    ss << "Has passphrase: ";
    append_boolean(ss, user.has_passphrase);
    ss << "\n";
    ss << "Has password: ";
    append_boolean(ss, user.has_password);
    ss << "\n";
    ss << "MFA active: ";
    append_boolean(ss, user.mfa_active);
    ss << "\n";

    if (!user.groups.empty())
    {
        ss << "Groups:\n";
        for (const auto &group : user.groups)
        {
            ss << "  ";
            append_styled_value(ss, group);
            ss << "\n";
        }
    }

    if (!user.security.is_null() && !user.security.empty())
    {
        ss << "Security:\n";
        for (auto it = user.security.begin(); it != user.security.end(); ++it)
        {
            ss << "  " << format_security_key(it.key()) << ": ";
            append_json_value(ss, it.value());
            ss << "\n";
        }
    }

    if (!user.tso.is_null() && !user.tso.empty())
    {
        append_segment_heading(ss, "TSO");
        if (user.tso.contains("tso:logon_procedure"))
            append_field(ss, "  Procedure:    ", user.tso["tso:logon_procedure"]);
        if (user.tso.contains("tso:account_number"))
            append_field(ss, "  Account:      ", user.tso["tso:account_number"]);
        if (user.tso.contains("tso:default_region_size"))
            append_field(ss, "  Region:       ", user.tso["tso:default_region_size"]);
        if (user.tso.contains("tso:max_region_size"))
            append_field(ss, "  Max region:   ", user.tso["tso:max_region_size"]);
        if (user.tso.contains("tso:dataset_allocation_unit"))
            append_field(ss, "  Alloc unit:   ", user.tso["tso:dataset_allocation_unit"]);
        if (user.tso.contains("tso:logon_command"))
            append_field(ss, "  Logon cmd:    ", user.tso["tso:logon_command"]);
        if (user.tso.contains("tso:user_data"))
            append_field(ss, "  User data:    ", user.tso["tso:user_data"]);
    }

    if (!user.omvs.is_null() && !user.omvs.empty())
    {
        append_segment_heading(ss, "OMVS");
        if (user.omvs.contains("omvs:uid"))
            append_field(ss, "  UID:   ", user.omvs["omvs:uid"]);
        if (user.omvs.contains("omvs:home_directory"))
            append_field(ss, "  Home:  ", user.omvs["omvs:home_directory"]);
        if (user.omvs.contains("omvs:default_shell"))
            append_field(ss, "  Shell: ", user.omvs["omvs:default_shell"]);
    }

    if (!user.kerberos.is_null() && !user.kerberos.empty())
    {
        append_segment_label(ss, "Kerberos");
        ss << " ";
        append_styled_value(ss, user.kerberos.dump());
        ss << "\n";
    }

    if (!user.cics.is_null() && !user.cics.empty())
    {
        append_segment_label(ss, "CICS");
        ss << " ";
        append_styled_value(ss, user.cics.dump());
        ss << "\n";
    }

    append_csdata(ss, user.csdata);

    return ss.str();
}

std::string TextFormatter::format(const GroupData &group)
{
    std::stringstream ss;

    append_field(ss, "Group: ", group.groupid);
    append_field(ss, "Owner: ", group.owner);
    append_field(ss, "Created: ", group.created_date);
    append_field(ss, "Superior group: ", group.superior_group);
    ss << "Universal: ";
    append_boolean(ss, group.universal);
    ss << "\n";

    if (!group.installation_data.empty())
    {
        append_field(ss, "Installation data: ", group.installation_data);
    }

    if (!group.connected_users.empty())
    {
        ss << "Users:\n";
        for (const auto &connected_user : group.connected_users)
        {
                ss << "  ";
                append_styled_value(ss, connected_user.userid);
                ss << " (";
                append_styled_value(ss, connected_user.authority);
                ss << ")\n";
        }
    }

    if (!group.omvs.is_null() && !group.omvs.empty())
    {
        append_segment_heading(ss, "OMVS");
        if (group.omvs.contains("omvs:gid"))
        {
            append_field(ss, "  GID: ", group.omvs["omvs:gid"]);
        }
    }

    append_csdata(ss, group.csdata);

    return ss.str();
}

std::string TextFormatter::format(const DatasetData &dataset)
{
    std::stringstream ss;

    append_field(ss, "Dataset: ", dataset.dataset);
    append_field(ss, "Owner: ", dataset.owner);
    append_field(ss, "UACC: ", dataset.uacc);
    ss << "Audited: ";
    append_boolean(ss, dataset.audited);
    ss << "\n";

    if (dataset.access_count > 0)
    {
        append_field(ss, "Access Count: ", dataset.access_count);
    }

    append_csdata(ss, dataset.csdata);

    append_access_list(ss, dataset.access_list);

    return ss.str();
}

std::string TextFormatter::format(const ResourceData &resource)
{
    std::stringstream ss;

    append_field(ss, "Resource: ", resource.resource);
    append_field(ss, "Class: ", resource.resource_class);
    append_field(ss, "Owner: ", resource.owner);
    append_field(ss, "UACC: ", resource.uacc);

    if (resource.base.contains("base:create_date"))
    {
        append_field(ss, "Created: ", resource.base["base:create_date"]);
    }

    append_csdata(ss, resource.csdata);

    append_access_list(ss, resource.access_list);

    return ss.str();
}

std::string TextFormatter::format(const GroupComparisonData &comparison)
{
    std::stringstream ss;

    if (comparison.raw_json_output)
    {
        ss << "Left response:\n";
        ss << (!comparison.left.response_json.is_null() && !comparison.left.response_json.empty()
                   ? comparison.left.response_json.dump(2)
                   : comparison.left.raw_response_json)
           << "\n";
        ss << "Right response:\n";
        ss << (!comparison.right.response_json.is_null() && !comparison.right.response_json.empty()
                   ? comparison.right.response_json.dump(2)
                   : comparison.right.raw_response_json)
           << "\n";
        return ss.str();
    }

    if (comparison.identical)
    {
        racshell::print_colored_text(ss, racshell::terminal_color::gray,
            "Groups " + comparison.left.groupid + 
            " and " + comparison.right.groupid +
            " are identical for compared fields.\n");
        return ss.str();
    }

    racshell::print_colored_text(ss,
                                 racshell::terminal_color::gray,
                                 "Comparing groups " + comparison.left.groupid + " and " + comparison.right.groupid + ":\n");
    for (auto it = comparison.differences.begin(); it != comparison.differences.end(); ++it)
    {
        if (it.key() == "connected_users")
        {
            const nlohmann::json &users = it.value();
            if (users.contains("only_in_left"))
            {
                racshell::colorize(ss, racshell::terminal_color::magenta) << "  Users only in " << comparison.left.groupid << ":\n";
                racshell::reset_color(ss);
                for (const auto &user : users["only_in_left"])
                {
                    ss << "    ";
                    append_styled_value(ss, user.value("userid", ""));
                    ss << " (";
                    append_styled_value(ss, user.value("authority", ""));
                    ss << ")\n";
                }
            }
            if (users.contains("only_in_right"))
            {
                racshell::colorize(ss, racshell::terminal_color::cyan) << "  Users only in " << comparison.right.groupid << ":\n";
                racshell::reset_color(ss);
                for (const auto &user : users["only_in_right"])
                {
                    ss << "    ";
                    append_styled_value(ss, user.value("userid", ""));
                    ss << " (";
                    append_styled_value(ss, user.value("authority", ""));
                    ss << ")\n";
                }
            }
            if (users.contains("authority_mismatches"))
            {
                racshell::print_colored_text(ss, racshell::terminal_color::gray, "  User authority differences\n");
                for (const auto &mismatch : users["authority_mismatches"])
                {
                    ss << "    ";
                    append_styled_value(ss, mismatch.value("userid", ""));
                    ss << ": ";
                    racshell::colorize(ss, racshell::terminal_color::magenta) << comparison.left.groupid;
                    racshell::reset_color(ss) << "='";
                    append_styled_value(ss, mismatch.value("left", ""));
                    ss << "', ";
                    racshell::colorize(ss, racshell::terminal_color::cyan) << comparison.right.groupid;
                    racshell::reset_color(ss) << "='";
                    append_styled_value(ss, mismatch.value("right", ""));
                    ss << "'\n";
                }
            }
            continue;
        }

        append_comparison_value(ss,
                                comparison.left.groupid,
                                comparison.right.groupid,
                                it.value(),
                                it.key());
    }

    return ss.str();
}

std::string TextFormatter::format(const UserComparisonData &comparison)
{
    std::stringstream ss;

    if (comparison.raw_json_output)
    {
        ss << "Left response:\n";
        ss << (!comparison.left.response_json.is_null() && !comparison.left.response_json.empty()
                   ? comparison.left.response_json.dump(2)
                   : comparison.left.raw_response_json)
           << "\n";
        ss << "Right response:\n";
        ss << (!comparison.right.response_json.is_null() && !comparison.right.response_json.empty()
                   ? comparison.right.response_json.dump(2)
                   : comparison.right.raw_response_json)
           << "\n";
        return ss.str();
    }

    if (comparison.identical)
    {
        racshell::print_colored_text(ss, racshell::terminal_color::gray,
            "Users " + comparison.left.userid + 
            " and " + comparison.right.userid +
            " are identical for compared fields.\n");
        return ss.str();
    }

    racshell::print_colored_text(ss,
                                 racshell::terminal_color::gray,
                                 "Comparing users " + comparison.left.userid + " and " + comparison.right.userid + ":\n");

    const std::array<const char *, 12> preferred_order = {
        "name",
        "owner",
        "default_group",
        "created_date",
        "revoked",
        "security",
        "tso",
        "kerberos",
        "cics",
        "groups",
        "omvs",
        "csdata"};

    const auto append_difference_by_key = [&](const std::string &key)
    {
        if (!comparison.differences.contains(key))
        {
            return;
        }

        const nlohmann::json &difference = comparison.differences[key];
        if (key == "groups")
        {
            racshell::colorize(ss, racshell::terminal_color::gray) << "  " << key;
            racshell::reset_color(ss) << ": \n";
            const nlohmann::json &groups = difference;
            if (groups.contains("only_in_left") && groups["only_in_left"].is_array() && !groups["only_in_left"].empty())
            {
                racshell::colorize(ss, racshell::terminal_color::magenta) << "    Groups only in " << comparison.left.userid << ":\n";
                racshell::reset_color(ss);
                for (const auto &group : groups["only_in_left"])
                {
                    ss << "    ";
                    append_styled_value(ss, racshell::value_to_text(group));
                    ss << "\n";
                }
            }
            if (groups.contains("only_in_right") && groups["only_in_right"].is_array() && !groups["only_in_right"].empty())
            {
                racshell::colorize(ss, racshell::terminal_color::cyan) << "    Groups only in " << comparison.right.userid << ":\n";
                racshell::reset_color(ss);
                for (const auto &group : groups["only_in_right"])
                {
                    ss << "    ";
                    append_styled_value(ss, racshell::value_to_text(group));
                    ss << "\n";
                }
            }
            return;
        }

        append_comparison_value(ss,
                                comparison.left.userid,
                                comparison.right.userid,
                                difference,
                                key);
    };

    for (const char *key : preferred_order)
    {
        append_difference_by_key(key);
    }

    for (auto it = comparison.differences.begin(); it != comparison.differences.end(); ++it)
    {
        if (std::find(preferred_order.begin(), preferred_order.end(), it.key()) != preferred_order.end())
        {
            continue;
        }

        append_difference_by_key(it.key());
    }

    return ss.str();
}
