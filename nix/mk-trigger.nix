{ pkgs, trigger }:

let
  lib = pkgs.lib;
  targetPkgs =
    if trigger.guestIsa == "x86_64" then
      pkgs.pkgsCross.musl64
    else if trigger.guestIsa == "aarch64" then
      pkgs.pkgsCross.aarch64-multiplatform-musl
    else
      throw "Unsupported reproducer guest ISA ${trigger.guestIsa}";
  stdenv = targetPkgs.stdenv;
  sourceArguments = lib.concatStringsSep " " (map lib.escapeShellArg trigger.sources);
  compileFlags = lib.concatStringsSep " " (map lib.escapeShellArg (
    [
      "-O2"
      "-g"
      "-static"
      "-fno-pie"
      "-no-pie"
      "-Wall"
      "-Wextra"
      "-Werror"
      "-Wl,--build-id=none"
    ]
    ++ trigger.cflags
    ++ lib.optionals trigger.freestanding [ "-nostdlib" ]
  ));
  publicTrigger = removeAttrs trigger [ "source" ];
in
stdenv.mkDerivation {
  pname = "focaccia-reproducer-${trigger.id}";
  version = "1";
  src = trigger.source;

  dontConfigure = true;
  dontStrip = true;
  hardeningDisable = [ "all" ];
  strictDeps = true;
  nativeBuildInputs = [ pkgs.binutils pkgs.gnugrep ];

  buildPhase = ''
    runHook preBuild
    $CC ${compileFlags} ${sourceArguments} -o reproducer-${trigger.id}

    ${pkgs.binutils}/bin/readelf -h reproducer-${trigger.id} \
      | ${pkgs.gnugrep}/bin/grep -F 'Type:' \
      | ${pkgs.gnugrep}/bin/grep -F 'EXEC'
    if ${pkgs.binutils}/bin/readelf -l reproducer-${trigger.id} \
        | ${pkgs.gnugrep}/bin/grep -Fq 'INTERP'; then
      echo 'Reproducer unexpectedly has an ELF interpreter' >&2
      exit 1
    fi
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 reproducer-${trigger.id} $out/bin/reproducer-${trigger.id}
    mkdir -p $out/share/focaccia-reproducers/${trigger.id}
    cat > $out/share/focaccia-reproducers/${trigger.id}/trigger.json <<'EOF'
    ${builtins.toJSON publicTrigger}
    EOF
    runHook postInstall
  '';

  meta = {
    description = "Focaccia paper trigger ${trigger.id}: ${trigger.instruction}";
    platforms = lib.platforms.linux;
  };
}
