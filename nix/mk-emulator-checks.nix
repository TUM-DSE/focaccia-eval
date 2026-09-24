{
  pkgs,
  lib,
  system,
  focaccia,
  qemuCaseEvaluationData,
  qemuEvaluationData,
  box64EvaluationData,
  nativeTriggerDefinitions,
  triggerPackages,
  box64Package,
  box64EvaluationConfig,
  offlineValidator,
  qemuPackages,
  qemuPlugin821,
  historicalEmulatorPackages,
}:

let
  # Configuration-only coverage: no emulator execution, debugger, RR, or oracle
  # generation. Discard store contexts so this check cannot realize those tools.
  paperEmulatorMatrixShape = builtins.unsafeDiscardStringContext (
    builtins.toJSON {
      inherit system;
      nativeGuests = lib.mapAttrs (_: trigger: trigger.guestIsa) nativeTriggerDefinitions;
      qemu = {
        inherit (qemuEvaluationData) role triggers applications emulatorCases;
        backends = lib.mapAttrs (_: emulator: emulator.backend) qemuEvaluationData.emulators;
      };
      box64 = {
        inherit (box64EvaluationData) role triggers applications emulatorCases;
        backends = lib.mapAttrs (_: emulator: emulator.backend) box64EvaluationData.emulators;
      };
      singleCases = lib.mapAttrs (_: data: data.emulatorCases) qemuCaseEvaluationData;
    }
  );
  paperEmulatorMatrixCheck =
    pkgs.runCommand "paper-emulator-guest-host-matrix" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        printf '%s\n' ${lib.escapeShellArg paperEmulatorMatrixShape} > matrix.json
        jq -e '
          . as $matrix |
          ["364", "2248", "2419"] as $arm |
          ["508", "1370", "1371", "1372", "1374", "1375", "1376", "1377",
           "1828867", "1832422", "1861404", "2175", "2495"] as $x86 |
          ([$matrix.qemu.emulatorCases | to_entries[] |
            select(.value.kind == "trigger") | .key] | sort) ==
            ([$arm[], $x86[] | "qemu-" + .] | sort) and
          all($matrix.qemu.emulatorCases | to_entries[];
            .key as $name | .value as $case |
            $case.guestSystem ==
              (if ($arm | index($case.trigger)) != null
               then "aarch64-linux" else "x86_64-linux" end) and
            $case.program == ("bin/qemu-" + ($case.guestSystem | sub("-linux$"; ""))) and
            $matrix.qemu.backends[$case.emulator] ==
              (if $case.trigger == "2248" then "qemu-plugin" else "qemu-gdb" end) and
            $matrix.singleCases[$name] == {($name): $case}) and
          ($matrix.singleCases | keys) == ($matrix.qemu.emulatorCases | keys) and
          $matrix.qemu.role == "qemu" and $matrix.box64.role == "box64" and
          all($matrix.qemu, $matrix.box64; .triggers == {} and .applications == {}) and
          ($matrix.nativeGuests | length) ==
            (if $matrix.system == "x86_64-linux" then 14 else 3 end) and
          all($matrix.nativeGuests[]; . + "-linux" == $matrix.system) and
          (if $matrix.system == "aarch64-linux" then
            ($matrix.box64.emulatorCases | keys) == ["box64-508"] and
            $matrix.box64.emulatorCases["box64-508"].guestSystem == "x86_64-linux" and
            $matrix.box64.emulatorCases["box64-508"].program == "bin/box64" and
            $matrix.box64.backends == {"box64-0-3-8": "box64-log"}
           else
            $matrix.system == "x86_64-linux" and
            $matrix.box64.emulatorCases == {} and $matrix.box64.backends == {}
           end)
        ' matrix.json > /dev/null
        mkdir -p "$out"
        cp matrix.json "$out/configuration.json"
      '';
  qemuCaseEvaluationShape = builtins.unsafeDiscardStringContext (
    builtins.toJSON (
      lib.mapAttrs (_: data: {
        caseNames = builtins.attrNames data.emulatorCases;
        emulatorNames = builtins.attrNames data.emulators;
        selectedEmulators = lib.unique (lib.mapAttrsToList (_: case: case.emulator) data.emulatorCases);
      }) qemuCaseEvaluationData
    )
  );
  qemuCaseEvaluationCheck =
    pkgs.runCommand "qemu-single-case-evaluation-closures" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        printf '%s\n' ${lib.escapeShellArg qemuCaseEvaluationShape} > shape.json
        jq -e 'all(.[];
          (.caseNames | length) == 1 and
          (.emulatorNames | length) == 1 and
          .emulatorNames == .selectedEmulators
        )' shape.json > /dev/null
        touch "$out"
      '';
  box64RegisterTraceCheck = pkgs.runCommand "box64-register-trace" { } ''
    binary=${triggerPackages."508-box64"}/bin/reproducer-508-box64
    trace="$TMPDIR/box64.log"
    start="$(${pkgs.binutils}/bin/nm -n "$binary" | ${pkgs.gawk}/bin/awk \
      '$3 == "focaccia_trace_start" { print $1 }')"
    stop="$(${pkgs.binutils}/bin/nm -n "$binary" | ${pkgs.gawk}/bin/awk \
      '$3 == "focaccia_trace_stop" { print $1 }')"
    trace_end="$(printf '%x' "$((16#$stop + 1))")"

    BOX64_TRACE="0x$start-0x$trace_end" \
    BOX64_TRACE_FILE=stderr \
    BOX64_DYNAREC_TRACE=1 \
      ${box64Package.box64-0-3-8}/bin/box64 "$binary" \
      > "$trace" 2>&1

    TRACE_LOG="$trace" START_ADDRESS="$start" STOP_ADDRESS="$stop" \
      ${focaccia.packages.${system}.focaccia}/bin/python3.12 - <<'PY'
    import os

    from focaccia.arch import x86
    from focaccia.parser import parse_box64

    with open(os.environ["TRACE_LOG"]) as stream:
        states = parse_box64(stream, x86.ArchX86())
    pcs = [state.read_register("RIP") for state in states]
    start = int(os.environ["START_ADDRESS"], 16)
    stop = int(os.environ["STOP_ADDRESS"], 16)
    if start not in pcs or stop not in pcs[pcs.index(start) + 1:]:
        raise SystemExit(
            f"Box64 trace lacks ordered bounds {start:#x}->{stop:#x}: {pcs!r}"
        )
    source = states[pcs.index(start)].read_register("RAX")
    destination = states[pcs.index(stop)].read_register("RAX")
    if source != 0x1234567812345678 or destination != 0x12345678:
        raise SystemExit(
            "Box64 did not reproduce CMPXCHG zero extension: "
            f"{source:#x}->{destination:#x}"
        )
    PY
    touch "$out"
  '';
  box64ReferenceValidationConfigCheck =
    pkgs.runCommand "box64-reference-validation-config" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        jq -e '
          .emulatorCases["box64-508"].trigger == "508-box64" and
          .emulatorCases["box64-508"].emulator == "box64-0-3-8" and
          .emulatorCases["box64-508"].expectedValidation == "mismatch" and
          ([.emulatorCases | keys[] | select(endswith("-reference"))] | length) == 0 and
          ([.emulators | keys[] | select(endswith("-reference"))] | length) == 0
        ' ${box64EvaluationConfig} > /dev/null
        touch "$out"
      '';
  box64CmpxchgRegressionCheck = pkgs.runCommand "box64-cmpxchg-regression" { } ''
    binary=${triggerPackages."508-box64"}/bin/reproducer-508-box64
    buggy_trace="$TMPDIR/buggy.log"
    reference_trace="$TMPDIR/reference.log"
    start="$(${pkgs.binutils}/bin/nm -n "$binary" | ${pkgs.gawk}/bin/awk \
      '$3 == "focaccia_trace_start" { print $1 }')"
    stop="$(${pkgs.binutils}/bin/nm -n "$binary" | ${pkgs.gawk}/bin/awk \
      '$3 == "focaccia_trace_stop" { print $1 }')"
    trace_end="$(printf '%x' "$((16#$stop + 1))")"

    capture() {
      local emulator="$1"
      local trace="$2"
      BOX64_TRACE="0x$start-0x$trace_end" \
      BOX64_TRACE_FILE=stderr \
      BOX64_DYNAREC_TRACE=1 \
        "$emulator" "$binary" > "$trace" 2>&1
    }
    capture ${box64Package.box64-0-3-8}/bin/box64 "$buggy_trace"
    capture ${box64Package.box64-0-3-8-reference}/bin/box64 "$reference_trace"

    BUGGY_TRACE="$buggy_trace" REFERENCE_TRACE="$reference_trace" \
    START_ADDRESS="$start" STOP_ADDRESS="$stop" \
      ${focaccia.packages.${system}.focaccia}/bin/python3.12 - <<'PY'
    import os

    from focaccia.arch import x86
    from focaccia.parser import parse_box64

    architecture = x86.ArchX86()
    start = int(os.environ["START_ADDRESS"], 16)
    stop = int(os.environ["STOP_ADDRESS"], 16)

    def register_at(trace_name, pc, register):
        with open(os.environ[trace_name]) as stream:
            states = parse_box64(stream, architecture)
        matching = [state for state in states if state.read_register("RIP") == pc]
        if len(matching) != 1:
            raise SystemExit(
                f"{trace_name} has {len(matching)} states at {pc:#x}"
            )
        return matching[0].read_register(register)

    initial = 0x1234567812345678
    corrupted = 0x12345678
    buggy_source = register_at("BUGGY_TRACE", start, "RAX")
    buggy_destination = register_at("BUGGY_TRACE", stop, "RAX")
    reference_source = register_at("REFERENCE_TRACE", start, "RAX")
    reference_destination = register_at("REFERENCE_TRACE", stop, "RAX")
    if (buggy_source, buggy_destination) != (initial, corrupted):
        raise SystemExit(
            "Injected Box64 does not reproduce the expected corruption: "
            f"{buggy_source:#x}->{buggy_destination:#x}"
        )
    if (reference_source, reference_destination) != (initial, initial):
        raise SystemExit(
            "Reference Box64 does not preserve RAX: "
            f"{reference_source:#x}->{reference_destination:#x}"
        )
    PY
    touch "$out"
  '';
  box64CmpxchgValidationCheck =
    pkgs.runCommand "box64-cmpxchg-validation" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        metadata=${../evaluation/fixtures/box64-cmpxchg/metadata.json}
        oracle=${../evaluation/fixtures/box64-cmpxchg/oracle.msgpack}
        binary=${../evaluation/fixtures/box64-cmpxchg/reproducer-508-box64}
        source=${../triggers/508-box64/main.c}
        mkdir -p "$out"

        jq -e '
          .schema == "focaccia-pinned-oracle-v1" and
          .case == "508-box64" and
          .producerSystem == "x86_64-linux" and
          .guestArchitecture == {"isa":"x86_64","endianness":"little"} and
          .producerFocacciaRevision == "edd7795632b3f7908ddfc4ce4b89619dc8ad485e" and
          .traceFormat == "msgpack" and
          .arguments == [] and .inputs == [] and
          .deterministicReplay == null
        ' "$metadata" > /dev/null

        source_hash="$(${pkgs.coreutils}/bin/sha256sum "$source" | ${pkgs.coreutils}/bin/cut -d' ' -f1)"
        binary_hash="$(${pkgs.coreutils}/bin/sha256sum "$binary" | ${pkgs.coreutils}/bin/cut -d' ' -f1)"
        oracle_hash="$(${pkgs.coreutils}/bin/sha256sum "$oracle" | ${pkgs.coreutils}/bin/cut -d' ' -f1)"
        expected_source_hash="$(jq -r .sourceSha256 "$metadata")"
        expected_binary_hash="$(jq -r .binarySha256 "$metadata")"
        expected_oracle_hash="$(jq -r .oracleSha256 "$metadata")"
        test "$source_hash" = "$expected_source_hash"
        test "$binary_hash" = "$expected_binary_hash"
        test "$oracle_hash" = "$expected_oracle_hash"

        start="$(${pkgs.binutils}/bin/nm -n "$binary" | ${pkgs.gawk}/bin/awk \
          '$3 == "focaccia_trace_start" { print $1 }')"
        stop="$(${pkgs.binutils}/bin/nm -n "$binary" | ${pkgs.gawk}/bin/awk \
          '$3 == "focaccia_trace_stop" { print $1 }')"
        jq -e \
          --argjson start "$((16#$start))" \
          --argjson stop "$((16#$stop))" \
          '.startAddress == $start and .stopAddress == $stop' \
          "$metadata" > /dev/null
        trace_end="$(printf '%x' "$((16#$stop + 1))")"

        capture() {
          local emulator="$1"
          local log="$2"
          BOX64_TRACE="0x$start-0x$trace_end" \
          BOX64_TRACE_FILE=stderr \
          BOX64_DYNAREC_TRACE=1 \
          BOX64_DYNAREC_DF=0 \
            "$emulator" "$binary" > "$log" 2>&1
        }
        capture ${box64Package.box64-0-3-8}/bin/box64 "$out/injected.log"
        capture ${box64Package.box64-0-3-8-reference}/bin/box64 "$out/reference.log"

        ${offlineValidator}/bin/focaccia-offline-validation \
          --backend box64 \
          --oracle "$oracle" \
          --trace-type msgpack \
          --log "$out/injected.log" \
          --report "$out/injected.json"
        ${offlineValidator}/bin/focaccia-offline-validation \
          --backend box64 \
          --oracle "$oracle" \
          --trace-type msgpack \
          --log "$out/reference.log" \
          --report "$out/reference.json"

        jq -e '
          .schema == "focaccia-offline-validation-v1" and
          .status == "mismatch" and
          .partialState == true and
          .validation.severity_counts.confirmed == 1 and
          ([.validation.entries[].errors[] |
            select(.severity == "confirmed" and
              .message == "Content of register RAX is false. Expected 0x1234567812345678, actual 0x12345678.")]
            | length) == 1
        ' "$out/injected.json" > /dev/null
        jq -e '
          .schema == "focaccia-offline-validation-v1" and
          .status == "incomplete" and
          .partialState == true and
          (.validation.severity_counts.confirmed // 0) == 0 and
          (.validation.severity_counts.possible // 0) == 0 and
          .validation.severity_counts.incomplete > 0 and
          ([.validation.entries[].errors[] |
            select(.severity == "confirmed" or .severity == "possible" or
              (.message | contains("register RAX")))] | length) == 0
        ' "$out/reference.json" > /dev/null
        cp "$metadata" "$out/oracle-metadata.json"
        cp "$oracle" "$out/oracle.msgpack"
        cp "$binary" "$out/reproducer-508-box64"
        cp "$source" "$out/main.c"
      '';
  qemuBmiWitnessFidelityCheck = pkgs.runCommand "qemu-bmi-witness-fidelity" { } ''
    run_expect() {
      local expected="$1"
      local emulator="$2"
      local binary="$3"
      set +e
      "$emulator" "$binary"
      local status=$?
      set -e
      if [ "$status" -ne "$expected" ]; then
        echo "Expected $binary under $emulator to exit $expected, got $status" >&2
        exit 1
      fi
    }

    buggy=${qemuPackages."qemu-7-2-0-user"}/bin/qemu-x86_64
    reference=${qemuPackages."qemu-9-0-0-user"}/bin/qemu-x86_64
    trigger_1371=${triggerPackages."1371"}/bin/reproducer-1371
    trigger_1372=${triggerPackages."1372"}/bin/reproducer-1372

    run_expect 71 "$buggy" "$trigger_1371"
    run_expect 72 "$buggy" "$trigger_1372"
    run_expect 0 "$reference" "$trigger_1371"
    run_expect 0 "$reference" "$trigger_1372"
    touch "$out"
  '';
  qemuOptimizerFidelityCheck = pkgs.runCommand "aarch64-lsr-optimizer-fidelity" { } ''
    trigger=${triggerPackages."2248"}/bin/reproducer-2248

    ulimit -c 0
    set +e
    ${qemuPlugin821}/bin/qemu-aarch64 "$trigger"
    historical_status=$?
    set -e
    if [ "$historical_status" -ne 1 ]; then
      echo "Historical QEMU 8.2.1 exited $historical_status, expected 1" >&2
      exit 1
    fi

    ${focaccia.packages.${system}.qemu-plugin}/bin/qemu-aarch64 "$trigger"
    touch "$out"
  '';
  qemuCvtps2pdFaultFidelityCheck = pkgs.runCommand "cvtps2pd-page-boundary-fault-fidelity" { } ''
    run_expect() {
      local expected="$1"
      local emulator="$2"
      local binary="$3"
      set +e
      "$emulator" "$binary"
      local status=$?
      set -e
      if [ "$status" -ne "$expected" ]; then
        echo "Expected $binary under $emulator to exit $expected, got $status" >&2
        exit 1
      fi
    }

    buggy=${qemuPackages."qemu-8-0-0-user"}/bin/qemu-x86_64
    reference=${qemuPackages."qemu-9-0-0-user"}/bin/qemu-x86_64
    trigger=${triggerPackages."1377"}/bin/reproducer-1377

    run_expect 139 "$buggy" "$trigger"
    run_expect 0 "$reference" "$trigger"
    touch "$out"
  '';
  emulatorPinsCheck = pkgs.writeText "historical-emulator-nixpkgs-pins.json" (
    builtins.toJSON (
      lib.mapAttrs (_: package: {
        version = package.actualVersion;
        inherit (package) nixpkgsRevision upstreamRevision;
        traceEnabled = package.traceEnabled;
      }) historicalEmulatorPackages
    )
    + "\n"
  );
in
{
  inherit
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
}
