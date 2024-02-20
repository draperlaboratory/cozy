{
  description = "visualizations for cozy";

  inputs.flake-utils.url  = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils}: flake-utils.lib.eachDefaultSystem (system:
  let 
    pkgs = nixpkgs.legacyPackages.${system};

    # this is derivation that sets up an environment to in which we have
    # development tools that let us do things like run bundler.mjs, which needs
    # esbuild's JS modules
    js-tools = pkgs.buildNpmPackage {
      name = "cozy-viz-tools";
      version = "0.0";
      src = ./.;
      buildInputs = [ pkgs.makeWrapper ];
      npmDepsHash = "sha256-zjrBTo7nqWNGBY0JhnxMIkCcQHc6rTveaPKcGPJyEKg=";
      dontNpmBuild = true;
      postInstall = ''
        mkdir -p $out/bin
        ln -s $out/lib/node_modules/cozy-viz/node_modules/.bin/* $out/bin
      '';
    };

    in {

      devShell = pkgs.mkShell { 
        buildInputs = [ 
          pkgs.nodePackages.vscode-langservers-extracted
          pkgs.nodePackages.typescript-language-server 
          pkgs.nodePackages.browser-sync
          pkgs.nodejs
          js-tools
        ]; 
      };

      defaultApp = {
        type = "app";
        program = "${js-tools}/bin/vite";
      };

      apps.bundle = let
        # this is a shell script for running bundler.mjs in that environment
        name = "bundle-cozy-viz";
        script = pkgs.writeShellScriptBin name ''
          node ${js-tools}/lib/node_modules/cozy-viz/bundler.mjs
        '';
        buildInputs = [ js-tools ]; 
        bundle = pkgs.symlinkJoin {
          name = name;
          paths = [script] ++ buildInputs;
          buildInputs = [ pkgs.makeWrapper ];
          postBuild = "wrapProgram $out/bin/${name} --prefix PATH : $out/bin";
        };
      in {
        type = "app";
        program = "${bundle}/bin/bundle-cozy-viz";
      };
  });
}
