"""conftest.py — Root pytest configuration.

Redirects tmp_path to a project-local directory to avoid Windows
permission issues with the default system temp location.
"""


def pytest_configure(config):
    """Set basetemp to a project-local directory."""
    if not config.option.__dict__.get("basetemp"):
        config.option.basetemp = ".pytest_tmp"
