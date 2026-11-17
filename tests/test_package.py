from importlib import resources

import eet_client


def test_type_marker_is_installed() -> None:
    assert resources.files(eet_client).joinpath("py.typed").is_file()
