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

    devShells.x86_64-linux.testing = pkgs.mkShell {
      buildInputs = [ 
        pkgs.python311
        pkgs.python311Packages.angr
        pkgs.python311Packages.networkx
        pkgs.python311Packages.sphinx
        pkgs.python311Packages.sphinx-autoapi
        self.packages.x86_64-linux.default
      ];
    };
  };
}
