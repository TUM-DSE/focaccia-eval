{ pkgs, sources, workloadsOnly ? false }:

let
  lib = pkgs.lib;
  targetPkgs = pkgs.pkgsCross.musl64;
  staticTargetPkgs = targetPkgs.pkgsStatic;
  x86Flags = builtins.concatStringsSep " " [
    "-mno-xsave"
    "-mno-xsaveopt"
    "-mno-xsavec"
    "-mno-xsaves"
    "-mno-avx"
    "-mno-avx2"
    "-mno-avx512f"
  ];
  commonOverrides = old: {
    dontStrip = true;
    hardeningDisable = (old.hardeningDisable or [ ]) ++ [ "pie" ];
    env = (old.env or { }) // {
      NIX_CFLAGS_COMPILE =
        "${old.env.NIX_CFLAGS_COMPILE or (old.NIX_CFLAGS_COMPILE or "")} ${x86Flags}";
    };
    separateDebugInfo = false;
  };

  mkSqlite = injected:
    staticTargetPkgs.sqlite.overrideAttrs (old: commonOverrides old // {
      pname = "focaccia-sqlite${lib.optionalString injected "-bug-508"}";
      version = "3.52.0";
      src = sources.sqlite;
      patches = lib.optionals injected [ ../applications/patches/sqlite-508.patch ];
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.tcl ];
      preBuild = ''
        export NIX_CFLAGS_LINK="$NIX_CFLAGS_LINK -lm"
      '';
      buildPhase = ''
        runHook preBuild
        make "B.cc=${pkgs.stdenv.cc}/bin/cc" sqlite3
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        install -Dm755 sqlite3 "$out/bin/sqlite3"
        runHook postInstall
      '';
      outputs = [ "out" ];
      postInstall = "";
      doCheck = false;
    });

  curlBase = staticTargetPkgs.curl.override {
    http2Support = false;
    opensslSupport = false;
    scpSupport = false;
    zlibSupport = false;
  };
  mkCurl = injected:
    curlBase.overrideAttrs (old: commonOverrides old // {
      pname = "focaccia-curl${lib.optionalString injected "-bug-2175"}";
      version = "8.18.0-dev";
      src = sources.curl;
      patches = [ ../applications/patches/curl-tracing-support.patch ]
        ++ lib.optionals injected [ ../applications/patches/curl-2175.patch ];
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.autoreconfHook ];
      postPatch = ''
        cp ${../applications/syscall-time.c} src/preload.c
        patchShebangs scripts
      '';
      preConfigure = ''
        rm -f src/tool_hugehelp.c
      '';
      outputs = [ "out" ];
      postInstall = "";
      doCheck = false;
    });

  mkLua = injected:
    staticTargetPkgs.stdenv.mkDerivation {
      pname = "focaccia-lua${lib.optionalString injected "-bug-2495"}";
      version = "5.5.0-dev";
      src = sources.lua;
      patches = [ ../applications/patches/lua-tracing-support.patch ]
        ++ lib.optionals injected [ ../applications/patches/lua-2495.patch ];
      postPatch = ''
        cp ${../applications/syscall-time.c} preload.c
        substituteInPlace makefile \
          --replace-fail 'CC= gcc' 'CC= ${staticTargetPkgs.stdenv.cc.targetPrefix}cc' \
          --replace-fail 'AR= ar rc' 'AR= ${staticTargetPkgs.stdenv.cc.targetPrefix}ar rc' \
          --replace-fail 'RANLIB= ranlib' 'RANLIB= ${staticTargetPkgs.stdenv.cc.targetPrefix}ranlib'
      '';
      hardeningDisable = [ "pie" ];
      dontStrip = true;
      NIX_CFLAGS_COMPILE = x86Flags;
      enableParallelBuilding = true;
      installPhase = ''
        runHook preInstall
        mkdir -p "$out/bin"
        cp lua "$out/bin/"
        runHook postInstall
      '';
    };

  sqlite = mkSqlite false;
  sqliteInjected = mkSqlite true;
  curl = mkCurl false;
  curlInjected = mkCurl true;
  lua = mkLua false;
  luaInjected = mkLua true;

  curlFixture = pkgs.writeText "curl-5k.bin" (
    lib.concatStrings (lib.replicate 80
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
  );
  workloads = pkgs.runCommand "focaccia-application-workloads" { } ''
    mkdir -p "$out/share/focaccia-evaluation/workloads"
    cp ${../applications/workloads/sqlite.sql} \
      "$out/share/focaccia-evaluation/workloads/sqlite.sql"
    cp ${../applications/workloads/lua.lua} \
      "$out/share/focaccia-evaluation/workloads/lua.lua"
    cp ${curlFixture} "$out/share/focaccia-evaluation/workloads/curl-5k.bin"
  '';

  catalog = pkgs.writeTextDir "share/focaccia-evaluation/applications.json" (
    builtins.toJSON {
      schema = "focaccia-application-catalog-v1";
      applications = {
        sqlite = {
          version = "3.52.0";
          sourceRevision = "a68046e79df161b2cd7a5408f483bc34ba36ea8f";
          injectionPoint = "local_getline";
          bug = "508";
          replayedEffects = "file I/O";
        };
        curl = {
          version = "8.18.0-dev";
          sourceRevision = "c6c4a99300bebdd3fd5a6af9ebca0053e3cbc8f7";
          injectionPoint = "Curl_sendrecv/sendrecv_dl";
          bug = "2175";
          replayedEffects = "socket I/O";
        };
        lua = {
          version = "5.5.0-dev";
          sourceRevision = "4cf498210e6a60637a7abb06d32460ec21efdbdc";
          injectionPoint = "laction";
          bug = "2495";
          replayedEffects = "signals";
        };
      };
    } + "\n"
  );

  injectionCheck = pkgs.runCommand "application-injections" {
    nativeBuildInputs = [ pkgs.binutils pkgs.jq ];
  } ''
    set -eu
    for binary in \
      ${sqlite}/bin/sqlite3 ${sqliteInjected}/bin/sqlite3 \
      ${curl}/bin/curl ${curlInjected}/bin/curl \
      ${lua}/bin/lua ${luaInjected}/bin/lua
    do
      if readelf -l "$binary" | grep -q 'Requesting program interpreter'; then
        echo "dynamically linked evaluation binary: $binary" >&2
        exit 1
      fi
    done

    objdump -d --disassemble=local_getline ${sqliteInjected}/bin/sqlite3 > sqlite-injected.S
    objdump -d --disassemble=local_getline ${sqlite}/bin/sqlite3 > sqlite-reference.S
    grep -Eiq '\bcmpxchg(l)?\b' sqlite-injected.S
    ! grep -Eiq '\bcmpxchg(l)?\b' sqlite-reference.S
    nm ${sqliteInjected}/bin/sqlite3 | grep -Eq \
      '[[:space:]][Tt][[:space:]]+focaccia_injection_sqlite_508$'
    nm ${sqliteInjected}/bin/sqlite3 | grep -Eq \
      '[[:space:]][Tt][[:space:]]+focaccia_trace_stop_sqlite$'

    objdump -d ${curlInjected}/bin/curl > curl-injected.S
    objdump -d ${curl}/bin/curl > curl-reference.S
    grep -Eiq '\bblsi\b' curl-injected.S
    ! grep -Eiq '\bblsi\b' curl-reference.S
    nm ${curlInjected}/bin/curl | grep -Eq \
      '[[:space:]][Tt][[:space:]]+focaccia_injection_curl_2175$'
    nm ${curlInjected}/bin/curl | grep -Eq \
      '[[:space:]][Tt][[:space:]]+focaccia_trace_stop_curl$'

    nm ${luaInjected}/bin/lua | grep -Eq '[[:space:]][Tt][[:space:]]+run$'
    ! nm ${lua}/bin/lua | grep -Eq '[[:space:]][Tt][[:space:]]+run$'
    objdump -d --disassemble=run ${luaInjected}/bin/lua > lua-injected.S
    grep -Eiq 'movq.*%mm0.*%r8' lua-injected.S
    nm ${luaInjected}/bin/lua | grep -Eq \
      '[[:space:]][Tt][[:space:]]+focaccia_injection_lua_2495$'
    nm ${luaInjected}/bin/lua | grep -Eq \
      '[[:space:]][Tt][[:space:]]+focaccia_trace_stop_lua$'

    test "$(wc -c < ${workloads}/share/focaccia-evaluation/workloads/curl-5k.bin)" -eq 5120
    jq -e '.schema == "focaccia-application-catalog-v1" and (.applications | length) == 3' \
      ${catalog}/share/focaccia-evaluation/applications.json >/dev/null

    ${lib.optionalString pkgs.stdenv.hostPlatform.isx86_64 ''
      mkdir work
      cd work
      ${sqliteInjected}/bin/sqlite3 evaluation.db < \
        ${workloads}/share/focaccia-evaluation/workloads/sqlite.sql >/dev/null
      ${curlInjected}/bin/curl --version >/dev/null
      ${luaInjected}/bin/lua -e 'print(_VERSION)' >/dev/null
    ''}
    touch "$out"
  '';
in {
  packages = {
    application-workloads = workloads;
    application-catalog = catalog;
  } // lib.optionalAttrs (!workloadsOnly) {
    application-sqlite = sqlite;
    application-sqlite-injected = sqliteInjected;
    application-curl = curl;
    application-curl-injected = curlInjected;
    application-lua = lua;
    application-lua-injected = luaInjected;
  };
  checks = lib.optionalAttrs (!workloadsOnly) {
    application-injections = injectionCheck;
  };
  inherit catalog curlFixture workloads;
}
