# This is a set of boilerplate helper functions for the test system

import os
import secrets
import subprocess
from pathlib import Path

import pytest

from sear import sear

_USER_NOT_FOUND_RETURN_CODES = {
    "racf_reason_code": 4,
    "racf_return_code": 4,
    "saf_return_code": 4,
    "sear_return_code": 4,
}

_USER_SUCCESS_RETURN_CODES = {
    "racf_reason_code": 0,
    "racf_return_code": 0,
    "saf_return_code": 0,
    "sear_return_code": 0,
}

_GROUP_NOT_FOUND_RETURN_CODES = {
    "racf_reason_code": 4,
    "racf_return_code": 4,
    "saf_return_code": 4,
    "sear_return_code": 4,
}

_GROUP_SUCCESS_RETURN_CODES = {
    "racf_reason_code": 0,
    "racf_return_code": 0,
    "saf_return_code": 0,
    "sear_return_code": 0,
}


@pytest.fixture
def generate_racf_userid() -> str:
    """Generates a valid 8 character long userid a RACF command can use"""
    return f"RSHU{secrets.token_hex(2)}".upper()

@pytest.fixture
def generate_racf_groupid() -> str:
    """Generates a valid 8 character long groupid a RACF command can use"""
    return f"RSHG{secrets.token_hex(2)}".upper()

@pytest.fixture
def generate_racf_resource_profile_name() -> str:
    """Generates a valid resource profile name a RACF command can use"""
    return f"racshell.test.prof{secrets.token_hex(2)}.**".upper()

def _run_command(binary: Path, *args: str):
    """Internal function"""
    return subprocess.run(
        [str(binary), *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


@pytest.fixture
def run_command():
    return _run_command

@pytest.fixture
def command_binary():
    """Returns a resolver for compiled RACSHELL command binaries."""
    default_build_dir = Path(__file__).resolve().parents[1] / "build" / "zos"
    build_dir = Path(os.environ.get("RACSHELL_BUILD_DIR", default_build_dir))

    def resolve(command: str) -> Path:
        for filename in (command, f"{command}.exe"):
            binary = build_dir / filename
            if binary.is_file():
                return binary
        raise FileNotFoundError(f"Could not find '{command}' in build directory {build_dir}")

    return resolve

def _sear_delete_user(userid: str):
    """Internal function"""

    return sear(
        {
            "operation": "delete",
            "admin_type": "user",
            "userid": userid,
        },
    ).result


def _sear_extract_user(userid: str):
    """Internal function"""
    return sear(
        {
            "operation": "extract",
            "admin_type": "user",
            "userid": userid,
        },
    ).result


@pytest.fixture
def delete_racf_user(generate_racf_userid):
    userid = generate_racf_userid
    existing_user = _sear_extract_user(userid)
    assert existing_user["return_codes"] == _USER_NOT_FOUND_RETURN_CODES

    yield userid

    current_user = _sear_extract_user(userid)
    if current_user["return_codes"] != _USER_NOT_FOUND_RETURN_CODES:
        assert current_user["return_codes"] == _USER_SUCCESS_RETURN_CODES
        deleted_user = _sear_delete_user(userid)
        assert deleted_user["return_codes"] == _USER_SUCCESS_RETURN_CODES

    remaining_user = _sear_extract_user(userid)
    assert remaining_user["return_codes"] == _USER_NOT_FOUND_RETURN_CODES


@pytest.fixture
def created_racf_user(delete_racf_user, command_binary, run_command):
    userid = delete_racf_user
    initial_name = "RACSHELL TEST USER"
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


def _sear_extract_group(groupid: str):
    """Internal function"""
    return sear(
        {
            "operation": "extract",
            "admin_type": "group",
            "group": groupid,
        },
    ).result


@pytest.fixture
def delete_racf_group(generate_racf_groupid):
    groupid = generate_racf_groupid
    existing_group = _sear_extract_group(groupid)
    assert existing_group["return_codes"] == _GROUP_NOT_FOUND_RETURN_CODES

    yield groupid

    current_group = _sear_extract_group(groupid)
    if current_group["return_codes"] != _GROUP_NOT_FOUND_RETURN_CODES:
        assert current_group["return_codes"] == _GROUP_SUCCESS_RETURN_CODES
        deleted_group = _sear_delete_group(groupid)
        assert deleted_group["return_codes"] == _GROUP_SUCCESS_RETURN_CODES

    remaining_group = _sear_extract_group(groupid)
    assert remaining_group["return_codes"] == _GROUP_NOT_FOUND_RETURN_CODES


@pytest.fixture
def created_racf_group(delete_racf_group, command_binary, run_command):
    groupid = delete_racf_group
    added = run_command(
        command_binary("addgroup"),
        groupid,
        "--json",
        "--no-color",
    )
    assert added.returncode == 0, added.stderr
    return {"groupid": groupid, "add_result": added}


def _sear_delete_resource_profile(class_name: str, resource_profile: str):
    """Internal function"""
    result = sear(
        {
            "operation": "delete",
            "admin_type": "resource",
            "resource": resource_profile,
            "class": class_name,
        },
    )

def _sear_delete_group(groupid: str):
    """Internal function"""
    return sear(
        {
            "operation": "delete",
            "admin_type": "group",
            "group": groupid,
        },
    ).result

def _sear_delete_dataset_profile(dataset_profile: str):
    """Internal function"""
    result = sear(
        {
            "operation": "delete",
            "admin_type": "dataset",
            "dataset": dataset_profile,
        },
    )

@pytest.fixture
def sear_extract_user(userid: str):
    """Extracts a user using SEAR"""
    result = sear(
        {
            "operation": "extract",
            "admin_type": "user",
            "userid": userid,
        },
    )
    yield 


@pytest.fixture
def sear_extract_resource_profile(class_name: str, resource_profile: str):
    pass

@pytest.fixture
def sear_extract_group(groupid: str):
    pass

@pytest.fixture
def sear_extract_dataset_profile(dataset_profile: str):
    pass
