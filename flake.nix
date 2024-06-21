{
  description = "The Cozy Comparitive Symbolic Evaluation Engine";

  outputs = { self, nixpkgs }:
  let 
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    pyPkgs = pkgs.python311.pkgs;

    portion = pyPkgs.buildPythonPackage rec {
      pname = "portion";
      version = "2.4.1";
      src = pyPkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-ncvxgIiY9ECu0wSl6fB0KihZ7KOwrH8fWOUFAoUqjvk=";
      };
      doCheck = false;
    };

    lld_15 = pkgs.lld_15.overrideAttrs (oa: {
      postInstall = "ln -s $out/bin/ld.lld $out/bin/ld.lld-15";
    });

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
        pyPkgs.lief
        pyPkgs.requests
        pyPkgs.angr
        pyPkgs.keystone-engine
        pyPkgs.intelhex
        lld_15
        pkgs.clang_15
      ];
    };

    latestTextual = pyPkgs.textual.overridePythonAttrs {
      version = "0.60.1";
      src = pkgs.fetchFromGitHub {
        owner = "Textualize";
        repo = "textual";
        rev = "refs/tags/v0.60.1";
        hash = "sha256-TyyI+Q61t2h0KLWc73pKcZXKVYNB+8mgoFqjAxM7TiE=";
      };
    };

    makeTests = conf : pkgs.stdenv.mkDerivation {
      name = "cozy-test-artifacts";
      src = ./.;
      buildInputs = [
        self.packages.x86_64-linux.default
        pkgs.python311
        patcherex2
      ];

      buildPhase = ''
        ${if conf.full_suite then "export FULL_SUITE=true" else ""}
        mkdir $out
        make -C ./test_programs
        for test in ./tests/*; do
          python $test
        done
        cp *.json $out/
      '';
    };


  in {

    packages.x86_64-linux.default = pyPkgs.buildPythonPackage {
      pname = "cozy";
      version = "0.0.1";
      format = "pyproject";
      src = ./.;
      buildInputs = [
        pkgs.python311Packages.hatchling
      ];
      propagatedBuildInputs = [
        portion
        pyPkgs.angr
        pyPkgs.networkx
        latestTextual
      ];
    };

    packages.x86_64-linux.tests = makeTests { full_suite = false; };

    packages.x86_64-linux.all_tests = makeTests { full_suite = true ; };

    devShells.x86_64-linux.default = pkgs.mkShell {
      shellHook = ''
        export PYTHONPATH="$(git rev-parse --show-toplevel)":$PYTHONPATH
      '';
      buildInputs = [ 
        pkgs.python311
        pyPkgs.angr
        pyPkgs.networkx
        pyPkgs.sphinx
        pyPkgs.sphinx-autoapi
        latestTextual
        portion
        patcherex2
      ];
    };

    templates.default = {
      path = ./cozy-template;
      description = "simple cozy project template";
      welcomeText = ''
              .::                               
           .::   .::                            
          .::          .::    .:::: .::.::   .::
          .::        .::  .::      .::  .:: .:: 
          .::       .::    .::   .::      .:::  
           .::   .:: .::  .::   .::        .::  
             .::::     .::    .::::::::   .::   
                                        .::     

      # The Cozy Compariative Symbolic Evaluator

      This is a cozy project template. 

      - To get started in an environment with cozy and its dependencies
      available, run `nix develop`.

      - to generate a cozy-script using the wizard, run `python -m cozy`.
      '';
    };
  };
}
