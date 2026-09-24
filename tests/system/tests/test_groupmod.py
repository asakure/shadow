"""
Test groupmod
"""

from __future__ import annotations

import re

import pytest
from passlib.hash import sha512_crypt
# from pytest_mh.conn import ProcessError

from framework.misc import shadow_password_pattern
from framework.roles.shadow import Shadow
from framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.Shadow)
def test_groupmod__set_password(shadow: Shadow):
    """
    :title: Set password for group
    :setup:
        1. Create group
    :steps:
        1. Set password for group
        2. Check group entry
        3. Check gshadow entry
    :expectedresults:
        1. Password is set successfully for group
        2. Group is found
        3. gshadow entry is found with new password
    :customerscenario: False
    """
    shadow.groupadd("tgroup")
    password = "Secret123"
    password_hash = sha512_crypt.hash(password)
    shadow.groupmod(f"-p '{password_hash}' tgroup")

    group_entry = shadow.tools.getent.group("tgroup")
    assert group_entry is not None, "Group should be found"
    assert group_entry.name == "tgroup", "Incorrect groupname"

    if shadow.host.features["gshadow"]:
        gshadow_entry = shadow.tools.getent.gshadow("tgroup")
        assert gshadow_entry is not None, "Group should be found"
        assert gshadow_entry.name == "tgroup", "Incorrect groupname"
        assert gshadow_entry.password is not None, "Password should not be None"
        assert re.match(shadow_password_pattern(), gshadow_entry.password), "Incorrect password"


@pytest.mark.topology(KnownTopology.Shadow)
def test_groupmod__set_password_no_gshadow_entry(shadow: Shadow):
    """
    :title: Set password for group with no corresponding gshadow entry
    :setup:
        1. Create group
        2. Remove gshadow entry manually
    :steps:
        1. Set password for group
        2. Check group entry
        3. Check gshadow entry
    :expectedresults:
        1. Password is set successfully for group
        2. Group is found
        3. gshadow entry is recreated
    :customerscenario: False
    """
    shadow.groupadd("tgroup")
    shadow.fs.sed("/^tgroup:/d", "/etc/gshadow", args=["-i"])
    password = "Secret123"
    password_hash = sha512_crypt.hash(password)
    shadow.groupmod(f"-p '{password_hash}' tgroup")

    group_entry = shadow.tools.getent.group("tgroup")
    assert group_entry is not None, "Group should be found"
    assert group_entry.name == "tgroup", "Incorrect groupname"

    if shadow.host.features["gshadow"]:
        gshadow_entry = shadow.tools.getent.gshadow("tgroup")
        assert gshadow_entry is not None, "Group should be found"
        assert gshadow_entry.name == "tgroup", "Incorrect groupname"
        assert gshadow_entry.password is not None, "Password should not be None"
#        assert re.match(shadow_password_pattern(), gshadow_entry.password), "Incorrect password"

# work-in-progress


@pytest.mark.topology(KnownTopology.Shadow)
def test_groupmod__set_password_no_gshadow_file(shadow: Shadow):
    """
    :title: Set password for group when no gshadow file exists
    :setup:
        1. Create group
        2. Remove /etc/gshadow file
    :steps:
        1. Set password for group
        2. Check group entry
        3. Verify that gshadow file doesn't exist
#        3. Verify that gshadow file exists
    :expectedresults:
        1. Password is set successfully for group
        2. Group is found
        3. No gshadow file is found
#        3. gshadow file is recreated
    :customerscenario: False
    """
    shadow.groupadd("tgroup")
    shadow.fs.rm("/etc/gshadow")
    password = "Secret123"
    password_hash = sha512_crypt.hash(password)
    shadow.groupmod(f"-p '{password_hash}' tgroup")

    group_entry = shadow.tools.getent.group("tgroup")
    assert group_entry is not None, "Group should be found"
    assert group_entry.name == "tgroup", "Incorrect groupname"
#    assert group_entry.password is not None, "Password should not be None"
#    assert re.match(shadow_password_pattern(), group_entry.password), "Incorrect password"

    if shadow.host.features["gshadow"]:
        gshadow_entry = shadow.tools.getent.gshadow("tgroup")
        assert gshadow_entry is not None, "Group should be found"
        assert gshadow_entry.name == "tgroup", "Incorrect groupname"
        assert gshadow_entry.password is None, "Password should not be found"
#        assert re.match(shadow_password_pattern(), gshadow_entry.password), "Incorrect password"
