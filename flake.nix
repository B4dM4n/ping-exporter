{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
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

      rustStable = pkgs.rust-bin.stable.latest.default.override {
        extensions = ["rust-src"];
        targets = ["x86_64-unknown-linux-musl"];
      };

      rustNightly = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);

      rustfmtNightly = pkgs.writeShellScriptBin "rustfmt" ''
        exec ${rustNightly}/bin/rustfmt "$@"
      '';
    in {
      devShell = pkgs.mkShell {
        preferLocalBuild = true;

        buildInputs = with pkgs; [
          rustfmtNightly
          rustStable
        ];
      };
    });
}
