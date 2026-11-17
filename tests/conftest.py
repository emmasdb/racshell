# This is a set of boilerplate helper functions for the test system

import secrets
import subprocess

import pytest

from sear import sear


@pytest.fixture
def generate_racf_userid() -> str:
    """Generates a valid 8 character long userid a RACF command can use"""
    return f"RSHU{secrets.token_hex(2)}".upper()

@pytest.fixture
def generate_racf_groupid() -> str:
    """Generates a valid 8 character long groupid a RACF command can use"""
    return f"RSHG{secrets.token_hex(2)}".upper()

@pytest.fixture
def run_shell_command(command: str):
    """Run a shell command using subprocess and capture its output."""
    output = subprocess.run(
        command, 
        text=False, 
        shell=True, 
        check=True, 
        capture_output=True,
        )
    return output

def _sear_delete_user(userid: str):
    """Internal function"""

    result = sear(
        {
            "operation": "delete",
            "admin_type": "user",
            "userid": userid,
        },
    )


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
    result = sear(
        {
            "operation": "delete",
            "admin_type": "group",
            "group": groupid,
        },
    )

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
    pass

@pytest.fixture
def sear_extract_resource_profile(class_name: str, resource_profile: str):
    pass

@pytest.fixture
def sear_extract_group(groupid: str):
    pass

@pytest.fixture
def sear_extract_dataset_profile(dataset_profile: str):
    pass
