"""The source distribution carries the package, its tests and its docs, and nothing else.

A working tree holds files that must never be published: session records, backlogs, scratch
review notes and helper scripts. Some are tracked, some are hidden only through
``.git/info/exclude`` or a nested ``.gitignore``, which hatchling does not read. The sdist is
therefore built from an allowlist, and this test builds one from the real tree and lists it.
"""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest
from hatchling.builders.sdist import SdistBuilder

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# hatchling force-includes the root .gitignore into every sdist (so a build from the unpacked
# sdist applies the same exclusions); no include/exclude setting removes it.
ALLOWED_TOP_LEVEL = frozenset({"PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "CHANGELOG.md", ".gitignore", "src", "tests", "docs"})
REQUIRED_TOP_LEVEL = frozenset({"PKG-INFO", "pyproject.toml", "src", "tests"})


def _build_sdist(directory: Path) -> Path:
    builder = SdistBuilder(str(PROJECT_ROOT))
    built = list(builder.build(directory=str(directory), versions=["standard"]))
    assert len(built) == 1, f"expected one sdist, got {built}"
    return Path(built[0])


def _member_names(sdist: Path) -> list[str]:
    with tarfile.open(sdist, "r:gz") as archive:
        return archive.getnames()


def _strip_root(names: list[str]) -> list[str]:
    """Drop the ``<name>-<version>/`` prefix every member carries."""
    return [name.split("/", 1)[1] for name in names if "/" in name]


@pytest.fixture(scope="module")
def sdist_members(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    sdist = _build_sdist(tmp_path_factory.mktemp("sdist"))
    members = _strip_root(_member_names(sdist))
    assert members, "the sdist is empty, so nothing below would be judged"
    return members


@pytest.mark.os_agnostic
def test_the_sdist_holds_only_allowlisted_top_level_entries(sdist_members: list[str]) -> None:
    top_level = {member.split("/", 1)[0] for member in sdist_members}

    unexpected = sorted(top_level - ALLOWED_TOP_LEVEL)
    missing = sorted(REQUIRED_TOP_LEVEL - top_level)

    assert not unexpected, f"the sdist ships files outside the allowlist: {unexpected}"
    assert not missing, f"the sdist lacks required entries: {missing}"


@pytest.mark.os_agnostic
def test_the_sdist_ships_only_the_package_under_src(sdist_members: list[str]) -> None:
    under_src = {member.split("/")[1] for member in sdist_members if member.startswith("src/") and member.count("/") >= 1}

    assert under_src == {"btx_lib_mail"}


@pytest.mark.os_agnostic
def test_the_sdist_carries_no_compiled_bytecode(sdist_members: list[str]) -> None:
    compiled = [member for member in sdist_members if "__pycache__" in member or member.endswith(".pyc")]

    assert not compiled, f"the sdist ships bytecode: {compiled[:5]}"
