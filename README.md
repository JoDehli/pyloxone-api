Pyloxone-api
============

A Python API for communicating with a [Loxone](http://www.loxone.com)
miniserver.
 
 

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyloxone-api?style=flat-square)
![PyPI - License](https://img.shields.io/pypi/l/pyloxone-api?style=flat-square)
[![PyPI](https://img.shields.io/pypi/v/pyloxone-api?style=flat-square)](https://pypi.python.org/pypi/pyloxone/)
 
 
 

Development
===========

We use [Poetry](https://python-poetry) for package and environment management,
[Black](https://pypi.org/project/black/) and [isort](https://pypi.org/project/isort/)
for code formatting, and [Pytest](https://pytest.org) for testing.

* Install [Poetry](https://python-poetry)

* Clone the project from Github, and use `Poetry` to install a virtual
  environment and all dependencies:
    ```shell
    > git clone https://github.com/jodehli/pyloxone-api
    > cd pyloxone-api
    > poetry install
    ```

* Create a shell in the virtual environment:
    ```shell
    > poetry shell
    ```

* To test, run `pytest`:
    ```shell
    > poetry shell
    > pytest
    ```

* There are some tests which require a live miniserver on the network. They are
  slower, and are not run by default. Be careful with these tests—they might
  make your miniserver behave oddly. To run them, you must specify appropriate
credentials, eg:

  ```bash
  > pytest --host=192.168.1.100 --port=80  --username=admin --password=admin
  ```
