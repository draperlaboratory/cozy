{
  description = "The Cozy Comparitive Symbolic Evaluation Engine";

  outputs = { self, nixpkgs }:
  let 
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    pyPkgs = pkgs.python311.pkgs;
  in {

    packages.x86_64-linux.default = pyPkgs.buildPythonPackage {
      pname = "cozy";
      version = "0.0.1";
      format = "pyproject";
      src = ./.;
      buildInputs = [
        pkgs.python311Packages.hatchling
      ];
    };

    devShells.x86_64-linux.testing = let 

      portion = pyPkgs.buildPythonPackage rec {
        pname = "portion";
        version = "2.4.1";
        src = pyPkgs.fetchPypi {
          inherit pname version;
          sha256 = "sha256-ncvxgIiY9ECu0wSl6fB0KihZ7KOwrH8fWOUFAoUqjvk=";
        };
        doCheck = false;
      };

      patcherex2 = pyPkgs.buildPythonPackage rec {
        pname = "patcherex2";
        version = "0.1.8";
        src = pyPkgs.fetchPypi {
          inherit pname version;
          sha256 = "sha256-tgzmOh0Ivb1yMAr1eivh0bHNBP1w5sLrZkkNFugglgI=";
        };
        pyproject = true;
        nativeBuildInputs = [
          pyPkgs.setuptools
        ];
        propagatedBuildInputs = [
          pyPkgs.keystone-engine
          pyPkgs.intelhex
        ];
      };

      lld_15 = pkgs.lld_15.overrideAttrs (oa: {
        postInstall = "ln -s $out/bin/ld.lld $out/bin/ld.lld-15";
      });

    in pkgs.mkShell {
      shellHook = ''
        export PYTHONPATH="$(git rev-parse --show-toplevel)":$PYTHONPATH
      '';
      buildInputs = [ 
        pkgs.python311
        pyPkgs.angr
        pyPkgs.networkx
        pyPkgs.sphinx
        pyPkgs.sphinx-autoapi
        pkgs.clang_15
        portion
        lld_15
        patcherex2
      ];
    };
  };
}
