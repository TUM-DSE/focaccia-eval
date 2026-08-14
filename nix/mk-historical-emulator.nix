{ pkgs, historicalPkgs, name, emulator, extraPatches ? [ ], pluginSource ? null, pluginSourceFile ? "contrib/plugins/focaccia.c" }:

let
  inherit (pkgs) lib;
  basePackage =
    if emulator.emulator == "qemu" then historicalPkgs.qemu
    else if emulator.emulator == "box64" then historicalPkgs.box64
    else throw "unsupported historical emulator: ${emulator.emulator}";
  traceEnabled = emulator.emulator == "box64";
  traceDecoder = historicalPkgs.zydis.overrideAttrs (previous: {
    cmakeFlags = (previous.cmakeFlags or [ ]) ++ [
      "-DZYDIS_BUILD_SHARED_LIB=ON"
    ];
  });
  package = if traceEnabled then basePackage.overrideAttrs (previous: {
    prePatch = (previous.prePatch or "") + lib.optionalString
      (emulator ? regressionPatch) ''
        ${pkgs.gnused}/bin/sed -i 's/\r$//' \
          src/dynarec/arm64/dynarec_arm64_0f.c
      '';
    patches = (previous.patches or [ ]) ++ lib.optional
      (emulator ? regressionPatch) emulator.regressionPatch;
    buildInputs = (previous.buildInputs or [ ]) ++ [ traceDecoder ];
    cmakeFlags = (previous.cmakeFlags or [ ]) ++ [ "-DHAVE_TRACE=ON" ];
  }) else if pluginSource != null then basePackage.overrideAttrs (previous: {
    patches = (previous.patches or [ ]) ++ extraPatches;
    postInstall = (previous.postInstall or "") + ''
      mkdir -p "$out/lib/plugins"
      $CC -fPIC -shared ${pluginSource}/${pluginSourceFile} \
        -o "$out/lib/plugins/libfocaccia.so" \
        -I"$out/include" \
        $(pkg-config --cflags glib-2.0) \
        $(pkg-config --libs glib-2.0)
    '';
    nativeBuildInputs = (previous.nativeBuildInputs or [ ]) ++ [ pkgs.pkg-config ];
  }) else basePackage;
  actualVersion = package.version or (lib.getVersion package);
  provenance = pkgs.writeTextDir
    "share/focaccia-reproducers/emulators/${name}.json"
    (builtins.toJSON {
      schema = "focaccia-emulator-provenance-v1";
      inherit name actualVersion traceEnabled;
      expectedVersion = emulator.version;
      fixedByRevision = emulator.fixedByRevision or null;
      regressionInjected = emulator ? regressionPatch;
      inherit (emulator) emulator nixpkgsRevision upstreamRevision;
      package = package.name;
    } + "\n");
in
assert lib.assertMsg (actualVersion == emulator.version)
  "${name}: Nixpkgs ${emulator.nixpkgsRevision} provides ${actualVersion}, expected ${emulator.version}";
pkgs.symlinkJoin {
  name = "${name}-historical";
  paths = [ package provenance ];
  nativeBuildInputs = lib.optionals traceEnabled [ pkgs.makeWrapper ];
  postBuild = lib.optionalString traceEnabled ''
    wrapProgram "$out/bin/box64" \
      --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath [ traceDecoder ]}
  '';

  passthru = {
    unwrapped = package;
    inherit actualVersion traceEnabled;
    inherit (emulator) nixpkgsRevision upstreamRevision;
  };

  meta = package.meta // {
    description = "${package.meta.description or name} (historical Nixpkgs ${emulator.nixpkgsRevision})";
  };
}
