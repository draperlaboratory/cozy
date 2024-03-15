{
  description = "A template for a cozy project";

  inputs = { 
    cozy.url = "github:draperlaboratory/cozy/develop";
  };

  outputs = { self, cozy, nixpkgs }:
  let 
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    cozyPkg = cozy.packages.x86_64-linux.default;
  in {
    devShell.x86_64-linux = pkgs.mkShell {
      buildInputs = [ 
        pkgs.python311
        cozyPkg
        pkgs.gum
      ];
    };
  };
}
