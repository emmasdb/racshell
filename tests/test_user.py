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

USER_NOT_FOUND_RETURN_CODES = {
	"racf_reason_code": 4,
	"racf_return_code": 4,
	"saf_return_code": 4,
	"sear_return_code": 4,
}

USER_SUCCESS_RETURN_CODES = {
	"racf_reason_code": 0,
	"racf_return_code": 0,
	"saf_return_code": 0,
	"sear_return_code": 0,
}


@pytest.fixture
def created_racf_user(command_binary, generate_racf_userid, request, run_command):
	userid = generate_racf_userid
	initial_name = "RACSHELL TEST USER"

	existing_user = sear(
		{
			"operation": "extract",
			"admin_type": "user",
			"userid": userid,
		},
	).result
	assert existing_user["return_codes"] == USER_NOT_FOUND_RETURN_CODES

	def cleanup_user():
		sear(
			{
				"operation": "delete",
				"admin_type": "user",
				"userid": userid,
			},
		)

	request.addfinalizer(cleanup_user)

	added = run_command(
		command_binary("adduser"),
		userid,
		"--name",
		initial_name,
		"--json",
		"--no-color",
	)
	assert added.returncode == 0, added.stderr
	return {"userid": userid, "initial_name": initial_name, "add_result": added}


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
	assert extracted_user["return_codes"] == USER_SUCCESS_RETURN_CODES
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
	assert missing_user["return_codes"] == USER_NOT_FOUND_RETURN_CODES
