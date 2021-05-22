Release Procedure
==================

This is the procedure for creating a new release of pyloxone-api.


We use [Poetry](https://python-poetry) for package management, and [Semantic Versioning](https://semver.org) for version numbering.

To create a new release:

* Check the version number currently in `pyproject.toml`.  Bump it up to the next version, which will be used for the release. Use `poetry version` to do this (and see [here](https://python-poetry.org/docs/cli/#version) for the options.), eg:
    ```bash
    poetry version minor
    ```

* Commit the change you have just made (if any) to `pyproject.toml`:
     ```bash
    git commit -am "Preparing for release v0.2"
    ```

* Tag the current state of the repository using git. Make sure that the release version number starts with 'v', eg: 

    ```bash
    git tag -a v0.2 -m "Release Version 0.2"
    ```

* Push the commit and the tag to Github:
    ```bash
    git push origin
    git push origin v0.2
    ```

* Publish the release to PyPI  (see [here](https://python-poetry.org/docs/cli/#publish)):
    ```bash
    poetry publish --build
    ```