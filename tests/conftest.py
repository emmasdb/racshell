# This is a set of boilerplate helper functions for the test system

import os
import secrets
import subprocess
from pathlib import Path

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
