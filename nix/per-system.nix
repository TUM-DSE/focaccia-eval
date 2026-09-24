{
  self,
  inputs,
  nixpkgs,
  focaccia,
  lib,
  catalog,
  emulatorVariants,
  paperTriggers,
  triggers,
}:

system:
let
  pkgs = import nixpkgs { inherit system; };
  plotOutputs = import ./mk-plots.nix { inherit pkgs; };
  inherit (plotOutputs)
    fontsConf
    package
    python
    runner
    ;
  nativeGuestIsa =
    if system == "x86_64-linux" then
      "x86_64"
    else if system == "aarch64-linux" then
      "aarch64"
    else
      throw "Unsupported evaluation system ${system}";
  nativeTriggerDefinitions = lib.filterAttrs (
    _: trigger: trigger.guestIsa == nativeGuestIsa
  ) triggers;
  plotPython = python;
  plotFontsConf = fontsConf;
  plotEvaluationRunner = runner;
  evaluationPlots = package;
  triggerPackages = lib.mapAttrs (
    _: trigger: import ./mk-trigger.nix { inherit pkgs trigger; }
  ) triggers;
  triggerWitnessHashes = lib.mapAttrs (
    _: trigger:
    builtins.hashString "sha256" (
      builtins.concatStringsSep "\n" (
        map (source: builtins.readFile (trigger.source + "/${source}")) trigger.sources
      )
    )
  ) triggers;
  applicationOutputs = import ./mk-applications.nix {
    inherit pkgs;
    workloadsOnly = system != "x86_64-linux";
    sources = {
      sqlite = inputs.sqlite-source;
      curl = inputs.curl-source;
      lua = inputs.lua-source;
    };
  };
  nativeApplicationDefinitions = lib.optionalAttrs (system == "x86_64-linux") {
    sqlite = {
      referenceBinary = "${applicationOutputs.packages."application-sqlite"}/bin/sqlite3";
      injectedBinary = "${applicationOutputs.packages."application-sqlite-injected"}/bin/sqlite3";
      workload = "${
        applicationOutputs.packages."application-workloads"
      }/share/focaccia-evaluation/workloads/sqlite.sql";
      workloadKind = "sqlite";
      expectedStatus = 0;
      startSymbol = "main";
      stopSymbol = "focaccia_trace_stop_sqlite";
    };
    curl = {
      referenceBinary = "${applicationOutputs.packages."application-curl"}/bin/curl";
      injectedBinary = "${applicationOutputs.packages."application-curl-injected"}/bin/curl";
      workload = "${
        applicationOutputs.packages."application-workloads"
      }/share/focaccia-evaluation/workloads/curl-5k.bin";
      workloadKind = "curl";
      expectedStatus = 0;
      startSymbol = "main";
      stopSymbol = "focaccia_trace_stop_curl";
    };
    lua = {
      referenceBinary = "${applicationOutputs.packages."application-lua"}/bin/lua";
      injectedBinary = "${applicationOutputs.packages."application-lua-injected"}/bin/lua";
      workload = "${
        applicationOutputs.packages."application-workloads"
      }/share/focaccia-evaluation/workloads/lua.lua";
      workloadKind = "lua";
      expectedStatus = 1;
      startSymbol = "main";
      stopSymbol = "focaccia_trace_stop_lua";
    };
  };
  fullCurlApplicationDefinitions = lib.optionalAttrs (system == "x86_64-linux") {
    curl-full = nativeApplicationDefinitions.curl // {
      traceMode = "full";
    };
  };
  qemuApplicationCases = lib.optionalAttrs (system == "aarch64-linux") {
    "qemu-app-sqlite" = {
      trigger = "sqlite";
      emulator = "qemu-6-1-0";
      workloadKind = "sqlite";
      expectedValidation = "mismatch";
      expectedMismatchSourceSymbol = "focaccia_injection_sqlite_508";
      expectedMismatchSubject = "RAX";
    };
    "qemu-app-curl" = {
      trigger = "curl";
      emulator = "qemu-8-2-0";
      workloadKind = "curl";
      expectedValidation = "mismatch";
      expectedMismatchSourceSymbol = "focaccia_injection_curl_2175";
      expectedMismatchSubject = "CF";
    };
    "qemu-app-lua" = {
      trigger = "lua";
      emulator = "qemu-9-0-0";
      workloadKind = "lua";
      expectedValidation = "mismatch";
      expectedMismatchSourceSymbol = "focaccia_injection_lua_2495";
      expectedMismatchSubject = "R8";
    };
  };
  qemuFullCurlCases = lib.optionalAttrs (system == "aarch64-linux") {
    "qemu-app-curl-full" = {
      trigger = "curl-full";
      emulator = "qemu-8-2-0";
      workloadKind = "curl";
      traceMode = "full";
      expectedValidation = "mismatch";
      expectedMismatchSourceSymbol = "focaccia_injection_curl_2175";
      expectedMismatchSubject = "CF";
    };
  };
  allQemuApplicationCases = qemuApplicationCases // qemuFullCurlCases;
  applicableEmulatorCases = lib.filterAttrs (
    _: case:
    let
      trigger = triggers.${case.trigger};
      variant = emulatorVariants.${case.emulator} or { emulator = "qemu"; };
    in
    # Table 1 includes both same-ISA and cross-ISA QEMU consumers. Oracle
    # selection remains guest-native, independent of this emulator host.
    (variant.emulator == "qemu" && builtins.elem trigger.guestIsa [ "x86_64" "aarch64" ])
    || (variant.emulator == "box64" && trigger.guestIsa == "x86_64" && system == "aarch64-linux")
  ) paperTriggers;
  emulatorTriggerCasesFor =
    family:
    lib.filterAttrs (
      _: case: (emulatorVariants.${case.emulator} or { emulator = "qemu"; }).emulator == family
    ) applicableEmulatorCases;
  emulatorCasesFor =
    family: emulatorTriggerCasesFor family // lib.optionalAttrs (family == "qemu") qemuApplicationCases;
  evaluationEmulatorsForCases =
    family: cases:
    let
      names = lib.unique (lib.mapAttrsToList (_: case: case.emulator) cases);
    in
    lib.genAttrs names (
      name:
      if name == "qemu-8-2-1-plugin" then
        {
          backend = "qemu-plugin";
          output = qemuPlugin821;
          version = "8.2.1";
        }
      else
        let
          variant = emulatorVariants.${name};
          output =
            if family == "qemu" then
              qemuPackages."${name}-user"
            else if family == "box64" then
              box64Package.${name}
            else
              throw "Unsupported evaluation emulator family ${family}";
        in
        {
          backend =
            if family == "qemu" then
              "qemu-gdb"
            else if family == "box64" then
              "box64-log"
            else
              "${family}-log";
          inherit output;
          inherit (variant) version;
        }
    );
  evaluationEmulatorCasesForCases =
    cases:
    lib.mapAttrs (
      name: case:
      let
        isApplication = builtins.hasAttr name allQemuApplicationCases;
        trigger = if isApplication then null else triggers.${case.trigger};
        variant = emulatorVariants.${case.emulator} or { emulator = "qemu"; };
        workloadName = {
          sqlite = "sqlite.sql";
          curl = "curl-5k.bin";
          lua = "lua.lua";
        };
      in
      {
        kind = if isApplication then "application" else "trigger";
        inherit (case) trigger emulator;
        guestSystem = if isApplication then "x86_64-linux" else "${trigger.guestIsa}-linux";
        program =
          if isApplication then
            "bin/qemu-x86_64"
          else if variant.emulator == "qemu" then
            "bin/qemu-${trigger.guestIsa}"
          else if variant.emulator == "box64" then
            "bin/box64"
          else
            "bin/${variant.emulator}";
        expectedValidation = case.expectedValidation or "mismatch";
      }
      // lib.optionalAttrs (!isApplication) {
        expectedWitnessSha256 = triggerWitnessHashes.${case.trigger};
      }
      // lib.optionalAttrs (case ? expectedMismatchSourceSymbol) {
        inherit (case) expectedMismatchSourceSymbol;
      }
      // lib.optionalAttrs (case ? expectedMismatchSubject) {
        inherit (case) expectedMismatchSubject;
      }
      // lib.optionalAttrs (case ? expectedMismatchCode) {
        inherit (case) expectedMismatchCode expectedMismatchLength;
      }
      // lib.optionalAttrs (case ? expectedMismatchSourceOffset) {
        inherit (case) expectedMismatchSourceOffset;
      }
      // lib.optionalAttrs (case ? expectedMismatchSourceAddress) {
        inherit (case) expectedMismatchSourceAddress;
      }
      // lib.optionalAttrs (case ? validationCutpoint) {
        inherit (case) validationCutpoint;
      }
      // lib.optionalAttrs (case ? qemuCpuModel) {
        inherit (case) qemuCpuModel;
      }
      // lib.optionalAttrs (case ? expectedTerminalSignal) {
        inherit (case) expectedTerminalSignal expectedFaultSymbol;
      }
      // lib.optionalAttrs isApplication (
        {
          workloadKind = case.workloadKind;
          traceMode = case.traceMode or "selective";
          workload = "${applicationOutputs.packages.application-workloads}/share/focaccia-evaluation/workloads/${
            workloadName.${case.workloadKind}
          }";
        }
        // lib.optionalAttrs (case.expectedValidation == "mismatch") {
          inherit (case) expectedMismatchSourceSymbol expectedMismatchSubject;
        }
      )
    ) cases;
  offlineValidator = pkgs.writeShellScriptBin "focaccia-offline-validation" ''
    exec ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
      ${../evaluation/offline_validation.py} \
      "$@"
  '';
  replayManifest = pkgs.writeShellScriptBin "focaccia-replay-manifest" ''
    exec ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
      ${../evaluation/replay_manifest.py} \
      "$@"
  '';
  replayPreflight = pkgs.writeShellScriptBin "focaccia-replay-preflight" ''
    exec ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
      ${../evaluation/replay_preflight.py} \
      "$@"
  '';
  mkEvaluationConfigData = role: family: cases: {
    schema = "focaccia-evaluation-config-v5";
    triggerTraceMode = "whole-program";
    inherit role system;
    captureProgram = focaccia.apps.${system}.capture-transforms.program;
    nmProgram = "${pkgs.binutils}/bin/nm";
    rrProgram = "${focaccia.packages.${system}.rr}/bin/rr";
    httpServerProgram = "${pkgs.python3}/bin/python";
    offlineValidatorProgram = "${offlineValidator}/bin/focaccia-offline-validation";
    validateQemuProgram = focaccia.apps.${system}.validate-qemu.program;
    replayManifestProgram = "${replayManifest}/bin/focaccia-replay-manifest";
    replayPreflightProgram = "${replayPreflight}/bin/focaccia-replay-preflight";
    triggers =
      if role == "native" then
        lib.mapAttrs (id: trigger: {
          binary = "${triggerPackages.${id}}/bin/reproducer-${id}";
          expectedStatus = trigger.expectedNativeStatus or 0;
          witnessSha256 = triggerWitnessHashes.${id};
        }) nativeTriggerDefinitions
      else
        { };
    applications = if role == "native" then nativeApplicationDefinitions else { };
    emulators = if family == null then { } else evaluationEmulatorsForCases family cases;
    emulatorCases = if family == null then { } else evaluationEmulatorCasesForCases cases;
  };
  mkEvaluationConfig =
    name: data: pkgs.writeText "focaccia-${name}-evaluation-config.json" (builtins.toJSON data + "\n");
  nativeEvaluationConfig = mkEvaluationConfig "native" (mkEvaluationConfigData "native" null { });
  nativeFullCurlEvaluationConfig = mkEvaluationConfig "native-curl-full" (
    (mkEvaluationConfigData "native" null { })
    // {
      triggers = { };
      applications = fullCurlApplicationDefinitions;
    }
  );
  qemuCases = emulatorCasesFor "qemu";
  qemuEvaluationData = mkEvaluationConfigData "qemu" "qemu" qemuCases;
  qemuEvaluationConfig = mkEvaluationConfig "qemu" qemuEvaluationData;
  qemuFullCurlEvaluationConfig = mkEvaluationConfig "qemu-curl-full" (
    mkEvaluationConfigData "qemu" "qemu" qemuFullCurlCases
  );
  qemuCaseEvaluationData = lib.mapAttrs (
    name: case: mkEvaluationConfigData "qemu" "qemu" { ${name} = case; }
  ) qemuCases;
  qemuCaseEvaluationConfigs = lib.mapAttrs (
    name: data: mkEvaluationConfig name data
  ) qemuCaseEvaluationData;
  box64EvaluationData = mkEvaluationConfigData "box64" "box64" (emulatorCasesFor "box64");
  box64EvaluationConfig = mkEvaluationConfig "box64" box64EvaluationData;
  x86ReproducerCompiler = pkgs.pkgsCross.gnu64.stdenv.cc;
  x86ReproducerCompilerProgram = "${x86ReproducerCompiler}/bin/${x86ReproducerCompiler.targetPrefix}cc";
  qemuReproducerReference = focaccia.packages.${system}.qemu-plugin;
  qemuReproducerReferenceVersion = qemuReproducerReference.version;
  reproducerEvaluationCases = {
    "508" = {
      sourceCase = "qemu-508";
      buggyEmulator = "qemu-6-1-0";
      buggyVersion = emulatorVariants.qemu-6-1-0.version;
      buggyProgram = "${qemuPackages.qemu-6-1-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-9-0-0";
      referenceVersion = emulatorVariants.qemu-9-0-0.version;
      referenceProgram = "${qemuPackages.qemu-9-0-0-user}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "RAX";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    "1370" = {
      sourceCase = "qemu-1370";
      buggyEmulator = "qemu-7-2-0";
      buggyVersion = emulatorVariants.qemu-7-2-0.version;
      buggyProgram = "${qemuPackages.qemu-7-2-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-current-reference";
      referenceVersion = qemuReproducerReferenceVersion;
      referenceProgram = "${qemuReproducerReference}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "CF";
      };
      sourceSymbol = "focaccia_trace_start";
      conditionCodeSeed = 1;
    };
    "1371" = {
      sourceCase = "qemu-1371";
      buggyEmulator = "qemu-7-2-0";
      buggyVersion = emulatorVariants.qemu-7-2-0.version;
      buggyProgram = "${qemuPackages.qemu-7-2-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-9-0-0";
      referenceVersion = emulatorVariants.qemu-9-0-0.version;
      referenceProgram = "${qemuPackages.qemu-9-0-0-user}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "CF";
      };
    };
    "1372" = {
      sourceCase = "qemu-1372";
      buggyEmulator = "qemu-7-2-0";
      buggyVersion = emulatorVariants.qemu-7-2-0.version;
      buggyProgram = "${qemuPackages.qemu-7-2-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-9-0-0";
      referenceVersion = emulatorVariants.qemu-9-0-0.version;
      referenceProgram = "${qemuPackages.qemu-9-0-0-user}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "RAX";
      };
    };
    "1374" = {
      sourceCase = "qemu-1374";
      buggyEmulator = "qemu-7-2-0";
      buggyVersion = emulatorVariants.qemu-7-2-0.version;
      buggyProgram = "${qemuPackages.qemu-7-2-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-9-0-0";
      referenceVersion = emulatorVariants.qemu-9-0-0.version;
      referenceProgram = "${qemuPackages.qemu-9-0-0-user}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "RAX";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    "1376" = {
      sourceCase = "qemu-1376";
      buggyEmulator = "qemu-7-2-0";
      buggyVersion = emulatorVariants.qemu-7-2-0.version;
      buggyProgram = "${qemuPackages.qemu-7-2-0-user}/bin/qemu-x86_64";
      referenceKind = "native-oracle";
      referenceEmulator = "native-x86-oracle";
      referenceVersion = "retained";
      primaryError = {
        code = "unexpected-guest-signal";
        subject = "SIGSEGV";
      };
      sourceSymbol = "focaccia_trace_start";
      requiredRegisters = [ "RAX" "RBX" ];
    };
    "1377" = {
      sourceCase = "qemu-1377";
      buggyEmulator = "qemu-8-0-0";
      buggyVersion = emulatorVariants.qemu-8-0-0.version;
      buggyProgram = "${qemuPackages.qemu-8-0-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-9-0-0";
      referenceVersion = emulatorVariants.qemu-9-0-0.version;
      referenceProgram = "${qemuPackages.qemu-9-0-0-user}/bin/qemu-x86_64";
      primaryError = {
        code = "unexpected-guest-signal";
        subject = "SIGSEGV";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    "1375" = {
      sourceCase = "qemu-1375";
      buggyEmulator = "qemu-7-2-0";
      buggyVersion = emulatorVariants.qemu-7-2-0.version;
      buggyProgram = "${qemuPackages.qemu-7-2-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-current-reference";
      referenceVersion = qemuReproducerReferenceVersion;
      referenceProgram = "${qemuReproducerReference}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "XMM1";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    "1828867" = {
      sourceCase = "qemu-1828867";
      buggyEmulator = "qemu-4-0-0";
      buggyVersion = emulatorVariants.qemu-4-0-0.version;
      buggyProgram = "${qemuPackages.qemu-4-0-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-current-reference";
      referenceVersion = qemuReproducerReferenceVersion;
      referenceProgram = "${qemuReproducerReference}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "RAX";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    "2175" = {
      sourceCase = "qemu-2175";
      buggyEmulator = "qemu-8-2-0";
      buggyVersion = emulatorVariants.qemu-8-2-0.version;
      buggyProgram = "${qemuPackages.qemu-8-2-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-current-reference";
      referenceVersion = qemuReproducerReferenceVersion;
      referenceProgram = "${qemuReproducerReference}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "CF";
      };
      sourceSymbol = "focaccia_trace_start";
      requiredRegisters = [ "CF" ];
    };
    "2495" = {
      sourceCase = "qemu-2495";
      buggyEmulator = "qemu-9-0-0";
      buggyVersion = emulatorVariants.qemu-9-0-0.version;
      buggyProgram = "${qemuPackages.qemu-9-0-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-current-reference";
      referenceVersion = qemuReproducerReferenceVersion;
      referenceProgram = "${qemuReproducerReference}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "R8";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    "1861404" = {
      sourceCase = "qemu-1861404";
      buggyEmulator = "qemu-4-2-0";
      buggyVersion = emulatorVariants.qemu-4-2-0.version;
      buggyProgram = "${qemuPackages.qemu-4-2-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-current-reference";
      referenceVersion = qemuReproducerReferenceVersion;
      referenceProgram = "${qemuReproducerReference}/bin/qemu-x86_64";
      primaryError = {
        code = "memory-content-mismatch";
        subject = "0x40007fcc20";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    "1832422" = {
      sourceCase = "qemu-1832422";
      buggyEmulator = "qemu-4-0-0";
      buggyVersion = emulatorVariants.qemu-4-0-0.version;
      buggyProgram = "${qemuPackages.qemu-4-0-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-current-reference";
      referenceVersion = qemuReproducerReferenceVersion;
      referenceProgram = "${qemuReproducerReference}/bin/qemu-x86_64";
      primaryError = {
        code = "unexpected-guest-signal";
        subject = "SIGILL";
      };
      sourceSymbol = "focaccia_trace_start";
    };
    sqlite = {
      sourceCase = "qemu-app-sqlite";
      buggyEmulator = "qemu-6-1-0";
      buggyVersion = emulatorVariants.qemu-6-1-0.version;
      buggyProgram = "${qemuPackages.qemu-6-1-0-user}/bin/qemu-x86_64";
      referenceEmulator = "qemu-9-0-0";
      referenceVersion = emulatorVariants.qemu-9-0-0.version;
      referenceProgram = "${qemuPackages.qemu-9-0-0-user}/bin/qemu-x86_64";
      primaryError = {
        code = "register-content-mismatch";
        subject = "RAX";
      };
      sourceSymbol = "focaccia_injection_sqlite_508";
    };
  };
  reproducerEvaluationConfig = pkgs.writeText "focaccia-reproducer-evaluation-config.json" (
    builtins.toJSON {
      schema = "focaccia-reproducer-evaluation-config-v2";
      inherit system;
      focacciaSourceIdentity =
        if focaccia ? rev then
          { kind = "git-revision"; value = focaccia.rev; }
        else
          { kind = "nix-store-path"; value = toString focaccia.outPath; };
      compilerProgram = x86ReproducerCompilerProgram;
      nmProgram = "${pkgs.binutils}/bin/nm";
      validateQemuProgram = focaccia.apps.${system}.validate-qemu.program;
      cases = reproducerEvaluationCases;
    }
    + "\n"
  );
  mkEvaluationRunner =
    name: config:
    pkgs.writeShellScriptBin name ''
      exec ${pkgs.python3}/bin/python \
        ${../evaluation/evaluation.py} \
        --config ${config} \
        "$@"
    '';
  legacyWitnessEvaluationRunners = lib.mapAttrs' (
    role: data:
    let name = "evaluate-${role}-legacy-witness";
    in lib.nameValuePair name (mkEvaluationRunner name (mkEvaluationConfig name (
      data // { triggerTraceMode = "legacy-witness"; }
    )))
  ) {
    native = mkEvaluationConfigData "native" null { };
    qemu = qemuEvaluationData;
    box64 = box64EvaluationData;
  };
  nativeEvaluationRunner = mkEvaluationRunner "evaluate-native" nativeEvaluationConfig;
  nativeFullCurlEvaluationRunner = mkEvaluationRunner "evaluate-native-curl-full" nativeFullCurlEvaluationConfig;
  qemuEvaluationRunner = mkEvaluationRunner "evaluate-qemu" qemuEvaluationConfig;
  qemuFullCurlEvaluationRunner = mkEvaluationRunner "evaluate-qemu-curl-full" qemuFullCurlEvaluationConfig;
  qemuCaseEvaluationRunners = lib.mapAttrs' (
    name: config: lib.nameValuePair "evaluate-${name}" (mkEvaluationRunner "evaluate-${name}" config)
  ) qemuCaseEvaluationConfigs;
  box64EvaluationRunner = mkEvaluationRunner "evaluate-box64" box64EvaluationConfig;
  reproducerEvaluationSources = pkgs.runCommand "focaccia-reproducer-evaluation-sources" { } ''
    mkdir -p "$out"
    cp ${../evaluation/evaluation.py} "$out/evaluation.py"
    cp ${../evaluation/reproducer_evaluation.py} \
      "$out/reproducer_evaluation.py"
  '';
  reproducerEvaluationRunner = pkgs.writeShellScriptBin "evaluate-reproducers" ''
    exec ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
      ${reproducerEvaluationSources}/reproducer_evaluation.py \
      --config ${reproducerEvaluationConfig} \
      "$@"
  '';
  mkEmulatorEvaluationRunner = import ./mk-emulator-runner.nix {
    inherit pkgs system;
  };
  emulatorEvaluationStages = [
    {
      label = "QEMU";
      program = "${qemuEvaluationRunner}/bin/evaluate-qemu";
    }
  ]
  ++ lib.optionals (system == "aarch64-linux") [
    {
      label = "QEMU reproducer effectiveness";
      program = "${reproducerEvaluationRunner}/bin/evaluate-reproducers";
    }
    {
      label = "Box64";
      program = "${box64EvaluationRunner}/bin/evaluate-box64";
    }
    {
      label = "QEMU full Curl";
      program = "${qemuFullCurlEvaluationRunner}/bin/evaluate-qemu-curl-full";
    }
  ];
  emulatorEvaluationRunner = mkEmulatorEvaluationRunner "evaluate-emulator" emulatorEvaluationStages;
  artifactCommandPackages = [
    nativeEvaluationRunner
    qemuEvaluationRunner
    emulatorEvaluationRunner
    plotEvaluationRunner
  ]
  ++ builtins.attrValues qemuCaseEvaluationRunners
  ++ lib.optionals (system == "x86_64-linux") [
    nativeFullCurlEvaluationRunner
  ]
  ++ lib.optionals (system == "aarch64-linux") [
    box64EvaluationRunner
    qemuFullCurlEvaluationRunner
    reproducerEvaluationRunner
  ];
  artifactCommandNames = [
    "evaluate-native"
    "evaluate-qemu"
    "evaluate-emulator"
    "plot-evaluation"
  ]
  ++ builtins.attrNames qemuCaseEvaluationRunners
  ++ lib.optionals (system == "x86_64-linux") [
    "evaluate-native-curl-full"
  ]
  ++ lib.optionals (system == "aarch64-linux") [
    "evaluate-box64"
    "evaluate-qemu-curl-full"
    "evaluate-reproducers"
  ];
  dockerOutputs = import ./mk-docker-artifact.nix {
    inherit
      pkgs
      self
      focaccia
      system
      ;
    nix2container = inputs.nix2container.packages.${system}.nix2container;
    dependencyPackages = [
      plotPython
      focaccia.packages.${system}.focaccia
      focaccia.packages.${system}.rr
    ]
    ++ map (emulator: emulator.output) (
      builtins.attrValues (evaluationEmulatorsForCases "qemu" qemuCases)
    )
    ++ lib.optionals (system == "aarch64-linux") [
      box64Package.box64-0-3-8
      x86ReproducerCompiler
    ];
    fontsConf = plotFontsConf;
    commandPackages = artifactCommandPackages;
    commandNames = artifactCommandNames;
  };
  dockerArtifactImage = dockerOutputs.image;
  dockerArtifactLoader = dockerOutputs.loadApplication;
  dockerArtifactInterfaceCheck = dockerOutputs.interfaceCheck;
  evaluationChecks = import ./mk-evaluation-checks.nix {
    inherit
      pkgs
      self
      focaccia
      lib
      system
      nativeTriggerDefinitions
      nativeApplicationDefinitions
      nativeEvaluationConfig
      nativeFullCurlEvaluationConfig
      qemuFullCurlEvaluationConfig
      qemuCaseEvaluationData
      triggerPackages
      qemuEvaluationData
      applicationOutputs
      mkEmulatorEvaluationRunner
      ;
  };
  inherit (evaluationChecks)
    codeNamingPolicyCheck
    nativeOracleIdentityCheck
    applicationOracleProducerHashCheck
    pluginReferenceAcceptanceCheck
    evaluationNativeCheck
    incrementalEvaluationCompositionCheck
    evaluationFullCurlModesCheck
    fullApplicationCompletionCheck
    wholeProgramAcceptanceCheck
    markerFreeTriggerWholeProgramCheck
    unannotatedTriggerFixture
    emulatorEvaluationDispatchCheck
    reproducerEffectivenessEvaluationCheck
    evaluationCaptureTimeoutCheck
    evaluationMsgpackDefaultCheck
    evaluationPersistenceTimingCheck
    evaluationProfileReportCheck
    evaluationTriggerBoundsCheck
    evaluationOfflineValidationCheck
    preRealizedEmulatorCheck
    evaluationEmulatorTraceFormatCheck
    evaluationQemuDriverCheck
    exactGuestSignalLocalizationCheck
    terminalValidationCutpointCheck
    unmatchedTransformSkippingCheck
    exactApplicationMismatchLocalizationCheck
    exactTriggerMismatchLocalizationCheck
    triggerMismatchWitnessBoundariesCheck
    referenceTerminalAcceptanceCheck
    qemuApplicationReplayCheck
    qemuCheckConfigurationIsolationCheck
    luaSignalReadinessCheck
    evaluationQemuPluginDriverCheck
    nativeWitnessIdentityCheck
    evaluationBox64DriverCheck
    box64WholeProgramCompletionCheck
    ;
  namedTriggerPackages = lib.mapAttrs' (
    id: package: lib.nameValuePair "trigger-${id}" package
  ) triggerPackages;
  mkHistoricalEmulator =
    name: emulator:
    import ./mk-historical-emulator.nix {
      inherit pkgs name emulator;
      historicalPkgs = import inputs.${emulator.input} { inherit system; };
    };
  qemuPlugin821 = import ./mk-historical-emulator.nix {
    inherit pkgs;
    historicalPkgs = import inputs.nixpkgs-qemu-8-2-1 { inherit system; };
    name = "qemu-8-2-1-plugin";
    emulator = emulatorVariants.qemu-8-2-1;
    extraPatches = [ ../emulators/patches/qemu-8.2.1-plugin-api.patch ];
    pluginSource = pkgs.runCommand "focaccia-qemu-8-2-1-plugin-source" { } ''
      mkdir -p "$out"
      cp ${../emulators/plugins/focaccia-qemu-8.2.1.c} "$out/focaccia-qemu-8.2.1.c"
      cp ${focaccia.packages.${system}.qemu-plugin-source}/contrib/plugins/focaccia.c \
        "$out/focaccia.c"
    '';
    pluginSourceFile = "focaccia-qemu-8.2.1.c";
  };
  qemuPackages = lib.mapAttrs' (
    name: emulator: lib.nameValuePair "${name}-user" (mkHistoricalEmulator name emulator)
  ) (lib.filterAttrs (_: emulator: emulator.emulator == "qemu") emulatorVariants);
  catalogPackage = pkgs.writeTextDir "share/focaccia-reproducers/catalog.json" (
    builtins.toJSON catalog + "\n"
  );
  triggerNamingCheck =
    pkgs.runCommand "trigger-catalog-naming"
      {
        nativeBuildInputs = [ pkgs.jq ];
      }
      ''
        cat >paper-case.jq <<'JQ'
        def nonempty_string: type == "string" and length > 0;
        def paper_case:
          if type != "object" then false else
            (.emulator | nonempty_string) and
            (.trigger | nonempty_string) and
            ((keys - [
              "emulator", "trigger", "validationCutpoint", "qemuCpuModel",
              "expectedTerminalSignal", "expectedFaultSymbol",
              "expectedMismatchSourceSymbol", "expectedMismatchSubject",
              "expectedMismatchSourceOffset", "expectedMismatchLength", "expectedMismatchCode"
            ]) | length == 0) and
            (if has("validationCutpoint") then
              .validationCutpoint == "stop"
            else true end) and
            (if has("qemuCpuModel") then
              (.qemuCpuModel | nonempty_string)
            else true end) and
            (if has("expectedTerminalSignal") then
              (.expectedTerminalSignal | nonempty_string)
            else true end) and
            (if has("expectedFaultSymbol") then
              (.expectedFaultSymbol | nonempty_string)
            else true end) and
            (if has("expectedMismatchSourceSymbol") then
              (.expectedMismatchSourceSymbol | nonempty_string)
            else true end) and
            (if has("expectedMismatchSubject") then
              (.expectedMismatchSubject | nonempty_string)
            else true end) and
            (if has("expectedMismatchSourceOffset") then
              (.expectedMismatchSourceOffset | type == "number" and . == floor and . >= 0)
            else true end) and
            (if has("expectedMismatchLength") then
              (.expectedMismatchLength | type == "number" and . == floor and . > 0)
            else true end) and
            (if has("expectedMismatchCode") then
              (.expectedMismatchCode == "register-content-mismatch" or
               .expectedMismatchCode == "memory-content-mismatch") and
              has("expectedMismatchSourceSymbol") and has("expectedMismatchSourceOffset") and
              has("expectedMismatchLength") and
              (if .expectedMismatchCode == "register-content-mismatch" then
                has("expectedMismatchSubject") else true end)
            else true end)
          end;
        JQ
        jq -e -L . '
          include "paper-case";
          .schema == "focaccia-trigger-catalog-v1" and
          (.triggers | length == 17) and
          (.paperTriggers | length == 17) and
          (keys | sort == [
            "authority", "emulators", "focaccia", "paperTriggers",
            "schema", "supportStatus", "triggers"
          ]) and
          ([.paperTriggers[] | paper_case] | all)
        ' ${catalogPackage}/share/focaccia-reproducers/catalog.json >/dev/null
        jq -ne -L . '
          include "paper-case";
          {emulator: "qemu-test", trigger: "test"} as $base |
          ["expectedTerminalSignal", "expectedFaultSymbol",
           "expectedMismatchSourceSymbol", "expectedMismatchSubject"] as $strings |
          ([
            $base,
            ($base + {validationCutpoint: "stop"}),
            ($base + {qemuCpuModel: "neoverse-v1"}),
            ($strings[] as $key | $base + {($key): "nonempty"})
          ] | all(paper_case)) and
          ([
            null, [], "case", 1,
            ($base | del(.emulator)), ($base | del(.trigger)),
            ($base + {unexpected: "value"}),
            ($base + {validationCutpoint: "start"}),
            ((["emulator", "trigger", "validationCutpoint", "qemuCpuModel"] + $strings)[] as $key |
              [null, false, 1, [], {}, ""][] as $value |
              $base + {($key): $value})
          ] | all(paper_case | not))
        ' >/dev/null
        jq -ne -L . '
          include "paper-case";
          {emulator: "qemu-test", trigger: "test",
           expectedMismatchSourceSymbol: "focaccia_trace_start",
           expectedMismatchSourceOffset: 0, expectedMismatchLength: 4,
           expectedMismatchCode: "memory-content-mismatch"} as $memory |
          ($memory + {expectedMismatchCode: "register-content-mismatch",
                      expectedMismatchSubject: "RAX"}) as $register |
          ([$memory, $register] | all(paper_case)) and
          ([
            ($register | del(.expectedMismatchSubject)),
            ($memory | del(.expectedMismatchSourceOffset)),
            ($memory | del(.expectedMismatchLength)),
            ($memory + {expectedMismatchCode: "unknown"}),
            ($memory + {expectedMismatchSourceOffset: -1}),
            ($memory + {expectedMismatchLength: 0}),
            (["expectedMismatchSourceOffset", "expectedMismatchLength"][] as $key |
              [null, false, "4", [], {}, 0.5][] as $value |
              $memory + {($key): $value})
          ] | all(paper_case | not))
        ' >/dev/null
        touch "$out"
      '';
  corpusPackage = pkgs.linkFarm "focaccia-reproducer-corpus" (
    lib.mapAttrsToList (id: package: {
      name = id;
      path = package;
    }) triggerPackages
  );
  box64Package = lib.optionalAttrs (system == "aarch64-linux") {
    box64-0-3-8 = mkHistoricalEmulator "box64-0-3-8" emulatorVariants.box64-0-3-8;
    box64-0-3-8-reference = mkHistoricalEmulator "box64-0-3-8-reference" emulatorVariants.box64-0-3-8-reference;
  };
  historicalEmulatorPackages = qemuPackages // box64Package;
  emulatorChecks = import ./mk-emulator-checks.nix {
    inherit
      pkgs
      lib
      system
      focaccia
      qemuCaseEvaluationData
      qemuEvaluationData
      box64EvaluationData
      nativeTriggerDefinitions
      triggerPackages
      box64Package
      box64EvaluationConfig
      offlineValidator
      qemuPackages
      qemuPlugin821
      historicalEmulatorPackages
      ;
  };
  inherit (emulatorChecks)
    paperEmulatorMatrixCheck
    qemuCaseEvaluationCheck
    box64RegisterTraceCheck
    box64ReferenceValidationConfigCheck
    box64CmpxchgRegressionCheck
    box64CmpxchgValidationCheck
    qemuBmiWitnessFidelityCheck
    qemuOptimizerFidelityCheck
    qemuCvtps2pdFaultFidelityCheck
    emulatorPinsCheck
    ;

in
{
  packages =
    namedTriggerPackages
    // qemuPackages
    // box64Package
    // qemuCaseEvaluationRunners
    // legacyWitnessEvaluationRunners
    // applicationOutputs.packages
    // {
      default = corpusPackage;
      corpus = corpusPackage;
      trigger-catalog = catalogPackage;
      unannotated-trigger-fixture = unannotatedTriggerFixture;
      evaluate-native = nativeEvaluationRunner;
      evaluate-qemu = qemuEvaluationRunner;
      evaluate-emulator = emulatorEvaluationRunner;
      evaluation-plots = evaluationPlots;
      evaluation-python = plotOutputs.python;
      docker-artifact = dockerArtifactImage;
      load-docker-artifact = dockerArtifactLoader;
      focaccia = focaccia.packages.${system}.focaccia;
      focaccia-qemu = focaccia.packages.${system}.qemu-plugin;
      qemu-8-2-1-plugin = qemuPlugin821;
      rr = focaccia.packages.${system}.rr;
    }
    // lib.optionalAttrs (system == "x86_64-linux") {
      evaluate-native-curl-full = nativeFullCurlEvaluationRunner;
    }
    // lib.optionalAttrs (system == "aarch64-linux") {
      evaluate-box64 = box64EvaluationRunner;
      evaluate-qemu-curl-full = qemuFullCurlEvaluationRunner;
      evaluate-reproducers = reproducerEvaluationRunner;
    };

  checks =
    lib.mapAttrs' (id: package: lib.nameValuePair "build-trigger-${id}" package) triggerPackages
    // applicationOutputs.checks
    // luaSignalReadinessCheck
    // {
      corpus-all = corpusPackage;
      trigger-catalog = catalogPackage;
      paper-trigger-libc-entry-context = import ./mk-libc-trigger-check.nix {
        inherit pkgs triggerPackages triggers paperTriggers;
      };
      trigger-naming = triggerNamingCheck;
      historical-emulator-nixpkgs-pins = emulatorPinsCheck;
      qemu-bmi-witness-fidelity = qemuBmiWitnessFidelityCheck;
      code-naming-policy = codeNamingPolicyCheck;
      native-oracle-identity = nativeOracleIdentityCheck;
      application-oracle-producer-hash = applicationOracleProducerHashCheck;
      plugin-reference-acceptance = pluginReferenceAcceptanceCheck;
      evaluate-native-interface = evaluationNativeCheck;
      evaluation-selective-applications = evaluationNativeCheck;
      full-curl-measurement-modes = evaluationFullCurlModesCheck;
      full-application-completion = fullApplicationCompletionCheck;
      whole-program-without-witness-stop-pc = wholeProgramAcceptanceCheck;
      marker-free-trigger-whole-program = markerFreeTriggerWholeProgramCheck;
      emulator-evaluation-dispatch = emulatorEvaluationDispatchCheck;
      reproducer-effectiveness-evaluation = reproducerEffectivenessEvaluationCheck;
      diagnostic-reproducer-source-admission = pkgs.runCommand
        "diagnostic-reproducer-source-admission" { } ''
          mkdir evaluation
          cp ${../evaluation/evaluation.py} evaluation/evaluation.py
          cp ${../evaluation/reproducer_evaluation.py} evaluation/reproducer_evaluation.py
          cp ${../evaluation/test_reproducer_evaluation.py} evaluation/test_reproducer_evaluation.py
          cd evaluation
          ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
            -m unittest -v test_reproducer_evaluation.DiagnosticAdapterTests
          touch "$out"
        '';
      aarch64-reproducer-concrete-dependencies = pkgs.runCommand
        "aarch64-reproducer-concrete-dependencies" { } ''
          mkdir evaluation
          cp ${../evaluation/evaluation.py} evaluation/evaluation.py
          cp ${../evaluation/reproducer_evaluation.py} evaluation/reproducer_evaluation.py
          cp ${../evaluation/aarch64_reproducer_evaluation.py} evaluation/aarch64_reproducer_evaluation.py
          cp ${../evaluation/test_aarch64_reproducer_evaluation.py} evaluation/test_aarch64_reproducer_evaluation.py
          cd evaluation
          ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
            -m unittest -v test_aarch64_reproducer_evaluation
          touch "$out"
        '';
      aarch64-generated-control-plugin-routing = pkgs.runCommand
        "aarch64-generated-control-plugin-routing" { } ''
          mkdir evaluation
          cp ${../evaluation/evaluation.py} evaluation/evaluation.py
          cp ${../evaluation/reproducer_evaluation.py} evaluation/reproducer_evaluation.py
          cp ${../evaluation/aarch64_reproducer_evaluation.py} evaluation/aarch64_reproducer_evaluation.py
          cp ${../evaluation/test_aarch64_reproducer_evaluation.py} evaluation/test_aarch64_reproducer_evaluation.py
          cd evaluation
          ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
            -m unittest -v test_aarch64_reproducer_evaluation.PluginControlTests
          touch "$out"
        '';
      aarch64-reproducer-entry-context-admission = pkgs.runCommand
        "aarch64-reproducer-entry-context-admission" { } ''
          mkdir evaluation
          cp ${../evaluation/evaluation.py} evaluation/evaluation.py
          cp ${../evaluation/reproducer_evaluation.py} evaluation/reproducer_evaluation.py
          cp ${../evaluation/test_reproducer_evaluation.py} evaluation/test_reproducer_evaluation.py
          cd evaluation
          ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
            -m unittest -v test_reproducer_evaluation.AArch64AdmissionTests
          touch "$out"
        '';
      reproducer-content-addressed-source-identity = reproducerEffectivenessEvaluationCheck;
      incremental-evaluation-composition = incrementalEvaluationCompositionCheck;
      evaluation-msgpack-default = evaluationMsgpackDefaultCheck;
      docker-artifact-interface = dockerArtifactInterfaceCheck;
      docker-artifact-transport-interface = dockerOutputs.transportCheck;
      docker-artifact-root-command-path = dockerOutputs.rootCommandPathCheck;
      nix2container-builder-interface = dockerOutputs.builderInterfaceCheck;
      profile-report-timings = evaluationProfileReportCheck;
      evaluation-capture-timeout = evaluationCaptureTimeoutCheck;
      profile-total-excludes-serialization = evaluationPersistenceTimingCheck;
      evaluation-trigger-bounds = evaluationTriggerBoundsCheck;
      pre-realized-emulator-outputs = preRealizedEmulatorCheck;
      evaluation-emulator-trace-format = evaluationEmulatorTraceFormatCheck;
      evaluation-box64-driver = evaluationBox64DriverCheck;
      box64-whole-program-completion = box64WholeProgramCompletionCheck;
      evaluation-qemu-driver = evaluationQemuDriverCheck;
      qemu-plugin-structured-localization = evaluationQemuPluginDriverCheck;
      native-witness-identity = nativeWitnessIdentityCheck;
      exact-guest-signal-localization = exactGuestSignalLocalizationCheck;
      terminal-validation-cutpoint = terminalValidationCutpointCheck;
      qemu-single-case-evaluation-closures = qemuCaseEvaluationCheck;
      paper-emulator-guest-host-matrix = paperEmulatorMatrixCheck;
      opt-in-unmatched-transform-skipping = unmatchedTransformSkippingCheck;
      exact-application-mismatch-localization = exactApplicationMismatchLocalizationCheck;
      exact-trigger-mismatch-localization = exactTriggerMismatchLocalizationCheck;
      trigger-mismatch-witness-boundaries = triggerMismatchWitnessBoundariesCheck;
      reference-terminal-acceptance = referenceTerminalAcceptanceCheck;
      qemu-application-deterministic-replay = qemuApplicationReplayCheck;
      qemu-check-configuration-isolation = qemuCheckConfigurationIsolationCheck;
      evaluation-offline-log-validation = evaluationOfflineValidationCheck;
      evaluation-plots = evaluationPlots;
      selective-application-acceptance = plotOutputs.selectiveApplicationAcceptanceCheck;
      whole-run-experiment-execution = plotOutputs.wholeRunExperimentExecutionCheck;
      fatal-diagnostic-eligibility = plotOutputs.fatalDiagnosticEligibilityCheck;
      data-driven-evaluation-plots = evaluationPlots;
      reproducer-size-measurement-fidelity = plotOutputs.sizeMeasurementCheck;
      explicit-profile-relocation = plotOutputs.profileRelocationCheck;
      host-separated-measurement-identity = plotOutputs.hostMeasurementIdentityCheck;
      exclusive-and-end-to-end-timing-accounting = plotOutputs.timingAccountingCheck;
      application-trend-ratio-normalization = plotOutputs.applicationTrendRatiosCheck;
      nix-plot-font-discovery = plotOutputs.fontDiscoveryCheck;
      provenance-bound-reproducer-sizes = evaluationPlots;
      rr-build = focaccia.packages.${system}.rr;
    }
    // lib.optionalAttrs (system == "aarch64-linux") {
      aarch64-lsr-optimizer-fidelity = qemuOptimizerFidelityCheck;
      cvtps2pd-page-boundary-fault-fidelity = qemuCvtps2pdFaultFidelityCheck;
      box64-register-trace = box64RegisterTraceCheck;
      box64-cmpxchg-regression = box64CmpxchgRegressionCheck;
      box64-cmpxchg-validation = box64CmpxchgValidationCheck;
      box64-reference-validation-config = box64ReferenceValidationConfigCheck;
      aarch64-native-rr-tool = focaccia.checks.${system}.aarch64-native-rr-tool;
    };

  apps =
    lib.mapAttrs (name: runner: {
      type = "app";
      program = "${runner}/bin/${name}";
    }) (qemuCaseEvaluationRunners // legacyWitnessEvaluationRunners)
    // {
      evaluate-native = {
        type = "app";
        program = "${nativeEvaluationRunner}/bin/evaluate-native";
      };
      evaluate-qemu = {
        type = "app";
        program = "${qemuEvaluationRunner}/bin/evaluate-qemu";
      };
      evaluate-emulator = {
        type = "app";
        program = "${emulatorEvaluationRunner}/bin/evaluate-emulator";
      };
      plot-evaluation = {
        type = "app";
        program = "${plotEvaluationRunner}/bin/plot-evaluation";
      };
      load-docker-artifact = {
        type = "app";
        program = "${dockerArtifactLoader}/bin/load-docker-artifact";
      };
      focaccia = focaccia.apps.${system}.default;
      capture-transforms = focaccia.apps.${system}.capture-transforms;
      validate-qemu = focaccia.apps.${system}.validate-qemu;
      rr = focaccia.apps.${system}.rr;
    }
    // lib.optionalAttrs (system == "x86_64-linux") {
      evaluate-native-curl-full = {
        type = "app";
        program = "${nativeFullCurlEvaluationRunner}/bin/evaluate-native-curl-full";
      };
    }
    // lib.optionalAttrs (system == "aarch64-linux") {
      evaluate-box64 = {
        type = "app";
        program = "${box64EvaluationRunner}/bin/evaluate-box64";
      };
      evaluate-qemu-curl-full = {
        type = "app";
        program = "${qemuFullCurlEvaluationRunner}/bin/evaluate-qemu-curl-full";
      };
      evaluate-reproducers = {
        type = "app";
        program = "${reproducerEvaluationRunner}/bin/evaluate-reproducers";
      };
    };

  devShells.default = pkgs.mkShell {
    FONTCONFIG_FILE = pkgs.makeFontsConf {
      fontDirectories = [ pkgs.libertine ];
    };
    packages = [
      focaccia.packages.${system}.focaccia
      focaccia.packages.${system}.rr
      pkgs.binutils
      pkgs.jq
      pkgs.fontconfig
      pkgs.libertine
      pkgs.ruff
      plotPython
    ];
  };
}
