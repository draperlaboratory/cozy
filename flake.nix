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
    in pkgs.mkShell {
      buildInputs = [ 
        pkgs.python311
        pkgs.python311Packages.angr
        pkgs.python311Packages.networkx
        pkgs.python311Packages.sphinx
        pkgs.python311Packages.sphinx-autoapi
        portion
        self.packages.x86_64-linux.default
      ];
    };
  };
}
