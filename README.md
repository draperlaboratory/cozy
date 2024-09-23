# cozy (Comparative Symbolic Execution)

cozy is a symbolic execution framework built around angr to enable comparative evaluation.
The goal of comparative evaluation is to determine the precise changes made by software
patches, specifically micropatches. cozy is capable of reporting observable changes
made by a micropatch, specifically to registers, memory and stdout/stderr. The framework
has the ability to present the behavioral changes caused by a patch in both a textual 
human-readable report and via a browser based rich user interface.



https://github.com/user-attachments/assets/2e72575f-0074-44a9-8412-2b17839b7b71



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
with using the framework.  To run the generator, install cozy, then run the
following command in the console:

```commandline
python3 -m cozy
```

The wizard will then prompt you with a series of questions and generate the
appropriate file with starter code. You'll need to provide:

1. a filename for your templated script,
2. the paths to the pre and postpatched binaries you wish to compare,
3. the name or address of the function where symbolic execution will begin,
4. the signature of that function (e.g. `int main(int argc, char* argv[])`)
5. a choice of whether to use
   [concolic](https://draperlaboratory.github.io/cozy/concolic.html) execution,
   and—if conconlic is used—whether or not to explore the space of program
   states,
6. a choice of whether to use any additional custom
   [hooks](https://draperlaboratory.github.io/cozy/hooks.html) (choosing "yes"
   will insert a stub for writing hooks into your cozy script but you'll want
   to write the hooks yourself),
7. a choice of whether to to request output in the form of a textual report or
   by launching the visualization server, and
8. a choice of whether to save the output in a JSON file which can be loaded
   into the visualizer in the future.

Afterwards, the cozy script will be written to the filename you supplied, for
example `my_script.py`. The cozy analysis can then be run, perhaps after some
modification to the script (like supplying some custom hooks), using `python
my_script.py`.

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

### Pushing Release to PyPI

This section is mostly for the cozy developers to remind us how to push to PyPI. See the page here for a more
advanced tutorial: https://packaging.python.org/en/latest/tutorials/packaging-projects/. Run the following commands to
push to PyPI:

```
pip3 install build
# Sometimes twine gets updates that are needed to work with the PyPI repo
pip3 install --upgrade twine
# Remember to bump the version numbers in pyproject.toml and setup.py
python3 -m build
# Remember if you haven't already to set up your PyPI token in ~/.pypirc
# Replace the version number with what you just built
python3 -m twine upload dist/cozy_re-1.5.0*
# Once you're done, make a release on Github and upload .whl and .tar.gz files that you just built. Enter changelog in the releases section.
```
