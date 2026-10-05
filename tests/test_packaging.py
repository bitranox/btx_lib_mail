"""The source distribution carries the package, its tests and its docs, and nothing else.

A working tree holds files that must never be published: session records, backlogs, scratch
review notes and helper scripts. Some are tracked, some are hidden only through
``.git/info/exclude`` or a nested ``.gitignore``, which hatchling does not read. The sdist is
therefore built from an allowlist, and this test builds one from the real tree and lists it.
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

import pytest
from hatchling.builders.sdist import SdistBuilder

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# hatchling force-includes the root .gitignore into every sdist (so a build from the unpacked
# sdist applies the same exclusions); no include/exclude setting removes it.
ALLOWED_TOP_LEVEL = frozenset({"PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "CHANGELOG.md", ".gitignore", "src", "tests", "docs"})
REQUIRED_TOP_LEVEL = frozenset({"PKG-INFO", "pyproject.toml", "src", "tests"})


def _build_sdist(directory: Path, root: Path = PROJECT_ROOT) -> Path:
    builder = SdistBuilder(str(root))
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


# Below each allowlisted directory only these file types are published. The include list names
# whole directories, so a stray note or a hidden scratch folder inside one would otherwise ship.
ALLOWED_SUFFIXES_BELOW = {"src/btx_lib_mail/": (".py", "py.typed"), "tests/": (".py",), "docs/": (".md",)}


def _strays_below_the_allowlisted_directories(members: list[str]) -> list[str]:
    """Return every member under src, tests or docs that is not an allowed file type, or hides in a dot-directory."""
    strays: list[str] = []
    for member in members:
        prefix = next((prefix for prefix in ALLOWED_SUFFIXES_BELOW if member.startswith(prefix)), None)
        if prefix is None or member.endswith("/"):
            continue
        relative = member[len(prefix) :]
        if any(part.startswith(".") for part in relative.split("/")) or not relative.endswith(ALLOWED_SUFFIXES_BELOW[prefix]):
            strays.append(member)
    return strays


@pytest.mark.os_agnostic
def test_the_sdist_ships_only_source_tests_and_markdown_below_its_directories(sdist_members: list[str]) -> None:
    files_below = [member for member in sdist_members if member.startswith(tuple(ALLOWED_SUFFIXES_BELOW))]
    assert files_below, "positive control: the sdist carries files under src, tests and docs"

    strays = _strays_below_the_allowlisted_directories(sdist_members)

    assert not strays, f"the sdist ships files that are not part of the package: {strays}"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "stray",
    ["docs/.private/session.md", "src/btx_lib_mail/REVIEW-NOTES.md", "tests/notes.txt", "docs/plans/draft.txt"],
)
def test_the_stray_check_catches_a_nested_stray(stray: str) -> None:
    assert _strays_below_the_allowlisted_directories(["src/btx_lib_mail/lib_mail.py", "docs/api.md", stray]) == [stray]


@pytest.mark.os_agnostic
def test_the_sdist_carries_no_compiled_bytecode(sdist_members: list[str]) -> None:
    compiled = [member for member in sdist_members if "__pycache__" in member or member.endswith(".pyc")]

    assert not compiled, f"the sdist ships bytecode: {compiled[:5]}"


# ---------------------------------------------------------------------------
# Built from a copy of the tree with strays planted, so the allowlist is judged even on a clean
# tree, and checked for completeness against a rule stated here independently of the include list.
# ---------------------------------------------------------------------------

PLANTED_STRAYS = (
    ".env",
    "handover.md",
    ".private/review.md",
    "docs/.private/session.md",
    "docs/notes.txt",
    "src/btx_lib_mail/NOTES.md",
    "src/btx_lib_mail/.hidden/scratch.py",
    "tests/.scratch.py",
    "tests/fixtures/notes.txt",
)
_COPIED_DIRECTORIES = ("src", "tests", "docs")


def _copy_of_the_tree(destination: Path) -> Path:
    """Copy the root files and the src, tests and docs trees: everything an sdist could pick up.

    A real ``.env`` holds tokens and stays out of the copy (pytest keeps its temp directories);
    a dummy one is planted among the strays instead.
    """
    destination.mkdir()
    for entry in PROJECT_ROOT.iterdir():
        if entry.is_file() and not entry.name.startswith(".env"):
            shutil.copyfile(entry, destination / entry.name)
    for directory in _COPIED_DIRECTORIES:
        shutil.copytree(PROJECT_ROOT / directory, destination / directory, ignore=shutil.ignore_patterns("__pycache__"))
    return destination


def _hidden(relative: Path) -> bool:
    return any(part.startswith(".") or part == "__pycache__" for part in relative.parts)


def _expected_in_sdist(root: Path) -> set[str]:
    """What the sdist must carry: every package module, top-level test, doc page, and the root metadata."""
    wanted = [
        *(root / "src" / "btx_lib_mail").rglob("*.py"),
        root / "src" / "btx_lib_mail" / "py.typed",
        *(root / "tests").glob("*.py"),
        *(root / "docs").rglob("*.md"),
        *(root / name for name in ("README.md", "LICENSE", "CHANGELOG.md", "pyproject.toml")),
    ]
    relatives = [path.relative_to(root) for path in wanted]
    return {relative.as_posix() for relative in relatives if not _hidden(relative)}


@pytest.fixture(scope="module")
def planted_build(tmp_path_factory: pytest.TempPathFactory) -> tuple[list[str], set[str]]:
    copy = _copy_of_the_tree(tmp_path_factory.mktemp("planted") / "project")
    expected = _expected_in_sdist(copy)
    for stray in PLANTED_STRAYS:
        target = copy / stray
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("not part of the package\n", encoding="utf-8")
    members = _strip_root(_member_names(_build_sdist(tmp_path_factory.mktemp("planted-sdist"), root=copy)))
    return members, expected


@pytest.mark.os_agnostic
def test_no_planted_stray_reaches_the_sdist(planted_build: tuple[list[str], set[str]]) -> None:
    members, _expected = planted_build

    shipped = sorted(set(PLANTED_STRAYS) & set(members))

    assert not shipped, f"the sdist ships files that are not part of the package: {shipped}"


@pytest.mark.os_agnostic
def test_the_sdist_carries_every_package_module_test_and_doc(planted_build: tuple[list[str], set[str]]) -> None:
    members, expected = planted_build
    assert "src/btx_lib_mail/cli/_dispatch.py" in expected, "positive control: a nested package module is expected"
    assert "docs/systemdesign/module_reference.md" in expected, "positive control: a nested doc is expected"

    missing = sorted(expected - set(members))

    assert not missing, f"the sdist lacks tracked files it must carry: {missing}"
