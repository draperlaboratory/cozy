# cozy (Comparative Symbolic Evaluation)

*(Formerly known as hungr)*

## Build Instructions

To get started with building cozy, run the following commands in the project root folder to create a virtual environment and install angr:

```commandline
python3 -m venv venv
source venv/bin/activate
pip3 install angr sphinx sphinx-autoapi
```

Alternatively, if you have `nix` installed and flakes enabled, run

``` 
nix develop .#testing 
```

To enter a nix development shell with `cozy` and its dependencies available on
`$PYTHONPATH`.

## Testing

To run an example comparison, run one of the example scripts. In the root directory, run the following commands:

```commandline
source venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:$PWD"
python3 examples/cmp_null_deref.py
```

Or just `python3 examples/cmp_null_deref.py` if you're in the nix development
shell.

### Building Docs

Building the docs requires the use of sphinx and sphinx-autoapi, which you should have previously installed via pip3. To build fresh HTML docs, run the following:

```commandline
source venv/bin/activate
cd docs
make html
```

The output documents should be stored in docs/build/html
