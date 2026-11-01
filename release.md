# Release procedure

Versions follow [Semantic Versioning](https://semver.org). Tags start with `v`.

1. Bump `version` in `pyproject.toml` and `__version__` in `src/pyloxone_api/__init__.py`. Keep them identical.
2. Run the tests: `uv run pytest`.
3. Build: `./scripts/build`. Check that `dist/` contains the sdist and the wheel.
4. Commit: `git commit -am "Release v0.x.y"`.
5. Tag: `git tag -a v0.x.y -m "Release v0.x.y"`.
6. Push commit and tag: `git push origin main` and `git push origin v0.x.y`.
7. Publish to PyPI: `uv publish dist/*`, or let the GitHub Actions publish workflow do it on the tag (once it exists).

Only after the release is on PyPI can the Loxone integration pin the new version in its `manifest.json`.
