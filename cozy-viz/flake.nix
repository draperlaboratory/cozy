{
  description = "visualizations for hungr";

  inputs.flake-utils.url  = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils}: flake-utils.lib.eachDefaultSystem (system:
  let 
    pkgs = nixpkgs.legacyPackages.${system};
    in {

      devShell = pkgs.mkShell { 
        buildInputs = [ 
          pkgs.nodePackages.vscode-langservers-extracted
          pkgs.nodePackages.typescript-language-server 
          pkgs.nodePackages.browser-sync
          pkgs.nodejs
        ]; 
      };

      packages.bundler = pkgs.buildNpmPackage {
        name = "cozy-viz-bundler";
        version = "0.0";
        src = ./.;
        npmDepsHash = "sha256-3DRXImi5vMZTJnLHJ3dtvQmeTDhqiFFlByudwvhYOV0=";
        dontNpmBuild = true;
      };

      defaultApp = let
        name = "serve-hungr-viz";
        script = pkgs.writeShellScriptBin name ''
          browser-sync start --listen 0.0.0.0 --server --index index.html --files="."
        '';
        buildInputs = [ 
          pkgs.nodePackages.browser-sync
          pkgs.nodejs
        ]; 
        serve = pkgs.symlinkJoin {
          name = name;
          paths = [script] ++ buildInputs;
          buildInputs = [ pkgs.makeWrapper ];
          postBuild = "wrapProgram $out/bin/${name} --prefix PATH : $out/bin";
        }; 
      in {
        type = "app";
        program = "${serve}/bin/serve-hungr-viz";
      };

      apps.bundle = let
        # this is derivation that sets up an environment to in which we can run
        # the included bundler.mjs, which needs esbuild's JS modules
        bundler = pkgs.buildNpmPackage {
          name = "cozy-viz-bundler";
          version = "0.0";
          src = ./.;
          npmDepsHash = "sha256-3DRXImi5vMZTJnLHJ3dtvQmeTDhqiFFlByudwvhYOV0=";
          dontNpmBuild = true;
        };

        # this is a shell script for running bundler.mjs in that environment
        name = "bundle-cozy-viz";
        script = pkgs.writeShellScriptBin name ''
          node ${bundler}/lib/node_modules/cozy-viz/bundler.mjs
        '';
        buildInputs = [ bundler ]; 
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
