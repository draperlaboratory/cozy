{
  description = "visualizations for hungr";

  inputs.flake-utils.url  = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils}: flake-utils.lib.eachDefaultSystem (system:
    let pkgs = nixpkgs.legacyPackages.${system};
    in {

      devShell = pkgs.mkShell { 
        buildInputs = [ 
          pkgs.nodePackages.vscode-langservers-extracted
          pkgs.nodePackages.typescript-language-server 
          pkgs.nodePackages.browser-sync
          pkgs.nodejs
        ]; 
      };

      serve = let
        name = "serve-hungr-viz";
        script = pkgs.writeShellScriptBin name ''
          browser-sync start --listen 0.0.0.0 --server --index index.html --files="."
          '';
        buildInputs = [ 
          pkgs.nodePackages.browser-sync
          pkgs.nodejs
        ]; 
      in pkgs.symlinkJoin {
        name = name;
        paths = [script] ++ buildInputs;
        buildInputs = [ pkgs.makeWrapper ];
        postBuild = "wrapProgram $out/bin/${name} --prefix PATH : $out/bin";
      };

      defaultApp = {
        type = "app";
        program = "${self.serve.${system}}/bin/serve-hungr-viz";
      };
  });
}