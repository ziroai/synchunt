"""
Packaging sanity tests.

The project is shipped both as a checkout (`python3 main.py`) and as an
installable console script (`pipx install synchunt` -> `synchunt`). These
tests keep the two in sync without needing a real install.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import __version__  # noqa: E402

tomllib = pytest.importorskip("tomllib", reason="tomllib needs Python 3.11+")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def pyproject():
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
        return tomllib.load(fh)


def test_project_metadata_matches_the_package(pyproject):
    project = pyproject["project"]
    assert project["name"] == "synchunt"
    assert project["version"] == __version__
    assert project["requires-python"].startswith(">=")
    assert "pyyaml" in " ".join(project["dependencies"]).lower()


def test_console_script_points_at_main_main(pyproject):
    scripts = pyproject["project"]["scripts"]
    assert scripts["synchunt"] == "main:main"
    # helper CLI shipped alongside the main entry point
    assert scripts["synchunt-tools"] == "tools_cli:main"

    import main as cli
    import tools_cli as tools

    assert callable(cli.main)
    assert callable(tools.main)
    # both entry points must be installed as importable top-level modules
    assert set(pyproject["tool"]["setuptools"]["py-modules"]) == {"main", "tools_cli"}


def test_declared_modules_exist(pyproject):
    setuptools_cfg = pyproject["tool"]["setuptools"]
    for module in setuptools_cfg["py-modules"]:
        assert os.path.exists(os.path.join(ROOT, f"{module}.py")), module
    for pattern in setuptools_cfg["packages"]["find"]["include"]:
        directory = pattern.rstrip("*")
        assert os.path.isdir(os.path.join(ROOT, directory)), directory


def test_dev_and_runtime_dependencies_are_separated(pyproject):
    deps = pyproject["project"]["dependencies"]
    dev = pyproject["project"]["optional-dependencies"]["dev"]
    assert not any("pytest" in dep for dep in deps)
    assert any("pytest" in dep for dep in dev)
