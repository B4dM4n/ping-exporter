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

      rust-nightly =
        (pkgs.rustChannelOf {
          sha256 = "sha256-tcbGLKsyRS9WASVCfs2fcLqA+WECB0l9SdfXO5vfpjI=";
          date = "2023-10-17";
          channel = "nightly";
        })
        .rust;

      rustfmt-nightly = pkgs.writeShellScriptBin "rustfmt" ''
        exec ${rust-nightly}/bin/rustfmt "$@"
      '';
    in {
      devShell = pkgs.mkShell {
        preferLocalBuild = true;

        buildInputs = with pkgs; [
          cargo
          clippy
          rust-analyzer
          rustc
          rustfmt-nightly
        ];
      };
    });
}
