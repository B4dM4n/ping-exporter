{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    mozilla.url = "github:mozilla/nixpkgs-mozilla";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    flake-utils,
    mozilla,
    nixpkgs,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system}.extend mozilla.overlays.rust;

      rust =
        (pkgs.rustChannelOf {
          sha256 = "sha256-54rlXRNdMMf/KXvzoXPXHfAFZW4vGoYsd5yy8MKG+dI=";
          date = "2023-04-19";
          channel = "nightly";
        })
        .rust;

      rustfmt = pkgs.writeShellScriptBin "rustfmt" ''
        exec ${rust}/bin/rustfmt "$@"
      '';
    in {
      devShell = pkgs.mkShell {
        preferLocalBuild = true;

        buildInputs = with pkgs; [
          cargo
          clippy
          rust-analyzer
          rustc
          rustfmt
        ];

        RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;
      };
    });
}
