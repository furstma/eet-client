# Contributing

Bug reports and pull requests are welcome. For anything larger than a fix,
please open an issue first to agree on the approach.

## Scope

The library does one thing: it reports a sale to the EET 2.0 service. Storing
records, scheduling repeated sends and integration with web frameworks belong
in the application that uses it. Simple and predictable is preferred over
configurable.

## Development

You need Python 3.11 or newer. With [uv](https://docs.astral.sh/uv/):

```console
$ uv sync
$ uv run ruff check
$ uv run ruff format --check
$ uv run mypy
$ uv run coverage run -m pytest
$ uv run coverage report
```

Without uv, `python -m pip install -e . --group dev` installs the same tools
into the active environment. It needs pip 25.1 or newer; a new virtual
environment on Python 3.11 or 3.12 has an older one, so run
`python -m pip install --upgrade pip` first.

CI runs the linters and the type checker on Python 3.11, the tests on every
supported Python version, and the tests once more with the oldest supported
versions of the dependencies.

Tests marked `live` need the network: they download the test certificates and
signed samples that the tax administration publishes, and exchange test
messages with its Playground. They run only when selected, with
`uv run pytest -m live`, and once a week in the Live workflow.

## Pull requests

- One concern per pull request, with tests.
- A change that users will notice gets a line under "Unreleased" in
  [CHANGELOG.md](CHANGELOG.md).
- Never commit a real certificate, private key, password or taxpayer
  identifier. Tests use keys generated at run time or the public Playground
  identities.

Security problems are reported privately, see [SECURITY.md](SECURITY.md).
