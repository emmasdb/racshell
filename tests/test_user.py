import json

import pytest

from sear import sear

USER_COMMANDS = (
	"adduser",
	"altuser",
	"deleteuser",
	"listuser",
	"searchusers",
	"compareusers",
	"resume",
	"revoke",
	"resetpassword",
	"resetpassphrase",
)

@pytest.mark.parametrize("command", USER_COMMANDS)
def test_user_command_help(command, command_binary, run_command):
	result = run_command(command_binary(command), "--help")

	assert result.returncode == 0, result.stderr
	assert command in result.stdout


def test_adduser_creates_user(created_racf_user):
	userid = created_racf_user["userid"]
	added = json.loads(created_racf_user["add_result"].stdout)

	assert added == {"userid": userid, "status": "created"}

	extracted_user = sear(
		{
			"operation": "extract",
			"admin_type": "user",
			"userid": userid,
		},
	).result
	assert extracted_user["return_codes"]["sear_return_code"] == 0
	assert extracted_user["profile"]["base"]["base:name"] == created_racf_user["initial_name"]


def test_listuser_outputs_user_details(created_racf_user, command_binary, run_command):
	userid = created_racf_user["userid"]
	result = run_command(command_binary("listuser"), userid, "--json", "--no-color")

	assert result.returncode == 0, result.stderr
	user = json.loads(result.stdout)
	assert user["userid"] == userid
	assert user["name"] == created_racf_user["initial_name"]


def test_altuser_updates_user_name(created_racf_user, command_binary, run_command):
	userid = created_racf_user["userid"]
	updated_name = "RACSHELL UPDATED USER"
	result = run_command(
		command_binary("altuser"),
		userid,
		"--name",
		updated_name,
		"--json",
		"--no-color",
	)

	assert result.returncode == 0, result.stderr
	assert json.loads(result.stdout) == {"userid": userid, "status": "altered"}

	listed = run_command(command_binary("listuser"), userid, "--json", "--no-color")
	assert listed.returncode == 0, listed.stderr
	assert json.loads(listed.stdout)["name"] == updated_name


def test_searchusers_finds_user(created_racf_user, command_binary, run_command):
	userid = created_racf_user["userid"]
	result = run_command(
		command_binary("searchusers"),
		"--filter",
		userid,
		"--json",
		"--no-color",
	)

	assert result.returncode == 0, result.stderr
	assert userid in json.loads(result.stdout)


def test_deleteuser_removes_user(created_racf_user, command_binary, run_command):
	userid = created_racf_user["userid"]
	result = run_command(
		command_binary("deleteuser"),
		userid,
		"--json",
		"--no-color",
	)

	assert result.returncode == 0, result.stderr
	assert json.loads(result.stdout) == {"userid": userid, "status": "deleted"}

	missing_user = sear(
		{
			"operation": "extract",
			"admin_type": "user",
			"userid": userid,
		},
	).result
	assert missing_user["return_codes"]["sear_return_code"] == 4
