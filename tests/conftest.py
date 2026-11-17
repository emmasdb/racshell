# This is a set of boilerplate helper functions for the test system

import secrets
import subprocess
from zipfile import Path

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
def generate_racf_resource_profile_name() -> str:
    """Generates a valid resource profile name a RACF command can use"""
    return f"racshell.test.prof{secrets.token_hex(2)}.**".upper()

@pytest.fixture
def run_command():
    """Run a binary with the given arguments and return the completed process."""
    def run(binary: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(binary), *args],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    return run

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
