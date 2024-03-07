{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.inputs.flake-utils.follows = "flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    flake-utils,
    nixpkgs,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system}.extend rust-overlay.overlays.default;

      rust-nightly = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);

      rustfmt-nightly = pkgs.writeShellScriptBin "rustfmt" ''
        exec ${rust-nightly}/bin/rustfmt "$@"
      '';
    in {
      devShell = pkgs.mkShell {
        preferLocalBuild = true;

        buildInputs = with pkgs; [
          cargo
          clippy
          rustc
          rustfmt-nightly
        ];
      };
    });
}
