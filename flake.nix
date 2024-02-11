{
  description = "Telegram Captcha Bot";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        devShells.default = pkgs.mkShell
          {
            packages = with pkgs; [
              go_1_22
              (golangci-lint.override { buildGoModule = buildGo122Module; })
            ];
          };
      });
}
