# cozy (Comparative Symbolic Execution)

cozy is a symbolic execution framework built around angr to enable comparative evaluation.
The goal of comparative evaluation is to determine the precise changes made by software
patches, specifically micropatches. cozy is capable of reporting observable changes
made by a micropatch, specifically to registers, memory and stdout/stderr. The framework
has the ability to dump diff information in both a textual human-readable report and
via a browser based rich user interface.

![Screenshot](screenshots/cozy-viz-1.png)

https://github.com/draperlaboratory/cozy/assets/53128179/0f5ab972-5d77-4723-9149-04c7427896d2

## Install

cozy is now available as a Python package on PyPI under the name `cozy-re`.
Install with pip via the following command:

```commandline
pip install cozy-re
```

## Documentation

The getting started guide and API reference can be found on our Github pages!:

https://draperlaboratory.github.io/cozy/

## Template Wizard

cozy now comes with a Python script template generator to help you get started
with using the framework. The wizard will prompt you with a series of questions
and generate the appropriate file with starter code. To run the generator,
install cozy, then run the following command in the console:

```commandline
python3 -m cozy
```

https://github.com/draperlaboratory/cozy/assets/53128179/ee1edf4d-4905-425c-9675-fe110bac7376

## About

cozy is being developed by Draper Laboratory under the [DARPA Assured
Micropatching (AMP)
program](https://www.darpa.mil/program/assured-micropatching).

# Run from Source

The following sections are for the case where you want to use cozy directly
from the source code in this repository, not from the `cozy-re` PyPI package.

## Setting up the Environment

To get started with building cozy, run the following commands in the project
root folder to create a virtual environment and install angr:

```commandline
python3 -m venv venv
source venv/bin/activate
pip3 install angr sphinx sphinx-autoapi networkx claripy portion textual
```

Alternatively, if you have `nix` installed and flakes enabled, run

```commandline
nix develop
```

To enter a nix development shell with `cozy` and its dependencies available on
`$PYTHONPATH`.

## Testing

To run an example comparison, run one of the example scripts. In the root
directory, run the following commands:

```commandline
source venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:$PWD"
python3 examples/cmp_null_deref.py
```

Or just `python3 examples/cmp_null_deref.py` if you're in the nix development
shell.

If nix is available, then to run the full suite of tests used in CI, you can
run:

```commandline
nix build .#tests
```

### Building Docs

Building the docs requires the use of sphinx and sphinx-autoapi, which you
should have previously installed via pip3. To build fresh HTML docs, run the
following:

```commandline
source venv/bin/activate
cd docs
make html
```

The output documents should be stored in docs/build/html
