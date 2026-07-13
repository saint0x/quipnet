{
  description = "Quicnet delivery infrastructure shell and validation checks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bash
            cargo
            git
            jq
            rustc
            rustfmt
          ];
        };

        formatter = pkgs.nixpkgs-fmt;

        checks.deploy = pkgs.runCommand "quicnet-deploy-check" {
          nativeBuildInputs = [ pkgs.ripgrep ];
        } ''
          cd ${self}
          ! rg -n "placeholder|sleep infinity|milestone1-skeleton|runtime image scaffold|deploy/runtime/config" README.md deploy
          ! rg -n "validate-scaffolding\\.sh" flake.nix
          touch $out
        '';
      });
}
