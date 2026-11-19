import json

import pytest

from sear import sear

GROUP_COMMANDS = (
    "addgroup",
    "altgroup",
    "deletegroup",
    "listgroup",
    "searchgroups",
    "comparegroups",
    "connect",
    "remove",
)


@pytest.mark.parametrize("command", GROUP_COMMANDS)
def test_group_command_help(command, command_binary, run_command):
    result = run_command(command_binary(command), "--help")

    assert result.returncode == 0, result.stderr
    assert command in result.stdout


def test_addgroup_creates_group(created_racf_group):
    groupid = created_racf_group["groupid"]
    added = json.loads(created_racf_group["add_result"].stdout)

    assert added == {"group": groupid, "status": "created"}

    extracted_group = sear(
        {
            "operation": "extract",
            "admin_type": "group",
            "group": groupid,
        },
    ).result
    assert extracted_group["return_codes"]["sear_return_code"] == 0


def test_listgroup_outputs_group_details(created_racf_group, command_binary, run_command):
    groupid = created_racf_group["groupid"]
    result = run_command(command_binary("listgroup"), groupid, "--json", "--no-color")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["groupid"] == groupid


def test_altgroup_assigns_automatic_gid(created_racf_group, command_binary, run_command):
    groupid = created_racf_group["groupid"]
    result = run_command(
        command_binary("altgroup"),
        groupid,
        "--omvs-auto-gid",
        "--json",
        "--no-color",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"group": groupid, "status": "altered"}

    extracted_group = sear(
        {
            "operation": "extract",
            "admin_type": "group",
            "group": groupid,
        },
    ).result
    assert extracted_group["return_codes"]["sear_return_code"] == 0


def test_searchgroups_finds_group(created_racf_group, command_binary, run_command):
    groupid = created_racf_group["groupid"]
    result = run_command(
        command_binary("searchgroups"),
        "--filter",
        groupid,
        "--json",
        "--no-color",
    )

    assert result.returncode == 0, result.stderr
    assert groupid in json.loads(result.stdout)


def test_deletegroup_removes_group(created_racf_group, command_binary, run_command):
    groupid = created_racf_group["groupid"]
    result = run_command(
        command_binary("deletegroup"),
        groupid,
        "--json",
        "--no-color",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"group": groupid, "status": "deleted"}

    missing_group = sear(
        {
            "operation": "extract",
            "admin_type": "group",
            "group": groupid,
        },
    ).result
    assert missing_group["return_codes"]["sear_return_code"] == 4
