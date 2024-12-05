{
  description = "The Cozy Comparitive Symbolic Evaluation Engine";

  outputs = { self, nixpkgs }:
  let 
    pkgs = nixpkgs.legacyPackages.x86_64-linux.extend (self: super: {
      unicorn = super.unicorn.overrideAttrs {
        version = "2.0.1"; #the nix package seems to have the version locked incorrectly to BELOW the exact unicorn version needed.
        src = self.fetchFromGitHub {
          owner = "unicorn-engine";
          repo = "unicorn";
          rev = "refs/tags/2.0.1.post1"; # XXX angr pins THIS version - cheating a bit
          sha256 = "sha256-Jz5C35rwnDz0CXcfcvWjkwScGNQO1uijF7JrtZhM7mI=";
        };
      };
    });

    pyPkgs = pkgs.python311.pkgs;

    portion = pyPkgs.buildPythonPackage rec {
      pname = "portion";
      version = "2.4.2";
      src = pyPkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-Uom0DZiVmxaz9pJ3gWeJNdPfG3wUlH9dd3jl4E3ZoGU=";
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

    # have had to override this in the past
    latestTextual = pyPkgs.textual;

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
