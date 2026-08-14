{
  description = "Reproducible Focaccia emulator-mistranslation corpus";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/3e3afe5174c561dee0df6f2c2b2236990146329f";

    focaccia = {
      url = "git+https://github.com/TUM-DSE/focaccia.git?ref=refs/heads/main";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    sqlite-source = {
      url = "github:ReimersS/sqlite/a68046e79df161b2cd7a5408f483bc34ba36ea8f";
      flake = false;
    };
    curl-source = {
      url = "github:curl/curl/c6c4a99300bebdd3fd5a6af9ebca0053e3cbc8f7";
      flake = false;
    };
    lua-source = {
      url = "github:lua/lua/4cf498210e6a60637a7abb06d32460ec21efdbdc";
      flake = false;
    };

    nixpkgs-qemu-4-0-0 = {
      url = "github:NixOS/nixpkgs/80bda4933272f7e244dc9702f39d18433988cdd0";
      flake = false;
    };
    nixpkgs-qemu-4-2-0 = {
      url = "github:NixOS/nixpkgs/2738ca86bd623934d816bef90f1867002c119950";
      flake = false;
    };
    nixpkgs-qemu-5-2-0 = {
      url = "github:NixOS/nixpkgs/a78ed5cbdd5427c30ca02a47ce6cccc9b7d17de4";
      flake = false;
    };
    nixpkgs-qemu-6-1-0 = {
      url = "github:NixOS/nixpkgs/f76bef61369be38a10c7a1aa718782a60340d9ff";
      flake = false;
    };
    nixpkgs-qemu-7-2-0 = {
      url = "github:NixOS/nixpkgs/1b7a6a6e57661d7d4e0775658930059b77ce94a4";
      flake = false;
    };
    nixpkgs-qemu-8-0-0 = {
      # Newest nixos-unstable revision indexed by nixpkgs-multiverse that
      # packages QEMU 8.0.0; its stock aarch64-linux output is cached.
      url = "github:NixOS/nixpkgs/a64b73e07d4aa65cfcbda29ecf78eaf9e72e44bd";
      flake = false;
    };
    nixpkgs-qemu-8-1-3 = {
      url = "github:NixOS/nixpkgs/4db6d0ab3a62ea7149386a40eb23d1bd4f508e6e";
      flake = false;
    };
    nixpkgs-qemu-8-2-0 = {
      url = "github:NixOS/nixpkgs/7a339d87931bba829f68e94621536cad9132971a";
      flake = false;
    };
    nixpkgs-qemu-8-2-1 = {
      url = "github:NixOS/nixpkgs/336eda0d07dc5e2be1f923990ad9fdb6bc8e28e3";
      flake = false;
    };
    nixpkgs-qemu-9-0-0 = {
      url = "github:NixOS/nixpkgs/3f878c71e15b53d8f817bb7aa95b5dce1b1071e1";
      flake = false;
    };

    nixpkgs-box64-0-3-8 = {
      url = "github:NixOS/nixpkgs/9fea8b5c5dbd756dd84c2c4c22430c896fd9a8a4";
      flake = false;
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      focaccia,
      ...
    }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = function: lib.genAttrs systems function;

      catalogData = import ./nix/catalog.nix { inherit focaccia lib; };
      inherit (catalogData)
        catalog
        emulatorVariants
        paperTriggers
        publicEmulators
        publicTriggers
        triggers
        ;
      perSystem = import ./nix/per-system.nix {
        inherit
          self
          inputs
          nixpkgs
          focaccia
          lib
          catalog
          emulatorVariants
          paperTriggers
          triggers
          ;
      };

    in
    {
      lib = {
        inherit
          catalog
          paperTriggers
          publicEmulators
          publicTriggers
          ;
      };
      packages = forAllSystems (system: (perSystem system).packages);
      checks = forAllSystems (system: (perSystem system).checks);
      apps = forAllSystems (system: (perSystem system).apps);
      devShells = forAllSystems (system: (perSystem system).devShells);
    };
}
