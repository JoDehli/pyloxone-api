import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--host",
        action="store",
        help="host name or IP address of miniserver. If not specified, online tests will be skipped",
    )
    parser.addoption(
        "--port", action="store", default="80", help="port for miniserver communication"
    )
    parser.addoption(
        "--username",
        action="store",
        default="admin",
        help="login username for miniserver",
    )
    parser.addoption(
        "--password",
        action="store",
        default="admin",
        help="password for miniserver communication",
    )
    parser.addoption(
        "--use-tls",
        action="store_true",
        default=False,
        help="use tls encryption",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "online: mark test as requiring online access")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--host"):
        return
    # No --host details provided. Mark 'online' tests to be skipped
    skip_online = pytest.mark.skip(reason="needs --host and credentials to run")
    for item in items:
        if "online" in item.keywords:
            item.add_marker(skip_online)


@pytest.fixture
def online_credentials(request):
    credentials = {}
    credentials["host"] = request.config.getoption("--host")
    credentials["port"] = request.config.getoption("--port")
    credentials["username"] = request.config.getoption("--username")
    credentials["password"] = request.config.getoption("--password")
    credentials["use_tls"] = request.config.getoption("--use-tls")
    return credentials
