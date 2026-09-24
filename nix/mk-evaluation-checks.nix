{
  pkgs,
  self,
  focaccia,
  lib,
  system,
  nativeTriggerDefinitions,
  nativeApplicationDefinitions,
  nativeEvaluationConfig,
  nativeFullCurlEvaluationConfig,
  qemuFullCurlEvaluationConfig,
  qemuCaseEvaluationData,
  triggerPackages,
  qemuEvaluationData,
  applicationOutputs,
  mkEmulatorEvaluationRunner,
}:

let
  # Fixture-only checks: producer/debugger/RR processes are fake test programs.
  mkIdentityFixtureCheck = name: tests:
    pkgs.runCommand name { nativeBuildInputs = [ pkgs.python3 pkgs.ruff ]; } ''
      mkdir evaluation
      cp ${../evaluation/evaluation.py} evaluation/evaluation.py
      cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
      cd evaluation
      ruff check evaluation.py test_evaluation.py
      ruff format --check evaluation.py test_evaluation.py
      python -m unittest -v ${lib.concatMapStringsSep " " (test: "test_evaluation.EvaluationTests.${test}") tests}
      touch "$out"
    '';
  nativeTriggerGdbserverCheck = pkgs.runCommand "native-trigger-gdbserver-transport" {
    nativeBuildInputs = [ pkgs.python3 pkgs.ruff pkgs.jq ];
  } ''
    mkdir evaluation
    cp ${../evaluation/evaluation.py} evaluation/evaluation.py
    cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
    cd evaluation
    ruff check evaluation.py test_evaluation.py
    ruff format --check evaluation.py test_evaluation.py
    python -m unittest -v test_evaluation.EvaluationTests.test_native_trigger_gdbserver_transport test_evaluation.EvaluationTests.test_gdbserver_readiness_does_not_connect test_evaluation.EvaluationTests.test_gdbserver_lifecycle_cleanup
    jq -e '.gdbserverProgram == "${pkgs.gdb}/bin/gdbserver" and (if .triggers | has("1861404") then .triggers."1861404".nativeTransport == "gdbserver" else true end)' ${nativeEvaluationConfig}
    test -x ${pkgs.gdb}/bin/gdbserver
    touch "$out"
  '';
  nativeOracleIdentityCheck = mkIdentityFixtureCheck "native-oracle-identity" [
    "test_native_oracle_identity_requires_explicit_producer_fields"
    "test_native_oracle_paths_reject_escape_and_allow_bundle_symlink"
    "test_qemu_emulated_role_launches_gdb_driver_and_checks_report"
  ];
  applicationOracleProducerHashCheck = mkIdentityFixtureCheck "application-oracle-producer-hash" [
    "test_application_oracle_requires_producer_hash"
    "test_native_selective_application_records_rr_and_uses_main_bound"
    "test_qemu_application_role_replays_bound_native_artifacts"
  ];
  pluginReferenceAcceptanceCheck = mkIdentityFixtureCheck "plugin-reference-acceptance" [
    "test_plugin_reference_acceptance_needs_no_mismatch_contract"
    "test_qemu_plugin_role_requires_complete_localized_mismatch"
  ];
  codeNamingPolicyCheck =
    pkgs.runCommand "code-naming-policy"
      {
        nativeBuildInputs = [ pkgs.gnugrep ];
      }
      ''
        numbered_fix_pattern="fi""x([-_]?[0-9]{3}|[0-9]{3}[A-Z])"
        private_issue_pattern="is""sue[ #:-]*[0-9]{3}|docs/is""sues/[0-9]{3}"
        ! grep -R -n -E "$numbered_fix_pattern|$private_issue_pattern" \
          ${self}/flake.nix ${self}/nix ${self}/evaluation \
          ${self}/applications ${self}/triggers
        touch "$out"
      '';
  evaluationNativeCheck =
    pkgs.runCommand "evaluate-native-interface"
      {
        nativeBuildInputs = [
          pkgs.jq
          pkgs.python3
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/offline_validation.py} evaluation/offline_validation.py
        cp ${../evaluation/replay_manifest.py} evaluation/replay_manifest.py
        cp ${../evaluation/replay_preflight.py} evaluation/replay_preflight.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        cp ${../evaluation/test_offline_validation.py} evaluation/test_offline_validation.py
        (
          cd evaluation
          ruff check evaluation.py offline_validation.py replay_manifest.py replay_preflight.py test_evaluation.py test_offline_validation.py
          ruff format --check evaluation.py offline_validation.py replay_manifest.py replay_preflight.py test_evaluation.py test_offline_validation.py
          python -m unittest -v test_evaluation.py
          python evaluation.py --help > "$TMPDIR/help.txt"
        )
        grep -F -- '--output' "$TMPDIR/help.txt"
        grep -F -- '--input' "$TMPDIR/help.txt"
        ! grep -F -- '--native' "$TMPDIR/help.txt"
        ! grep -F -- '--emulated' "$TMPDIR/help.txt"
        jq -e \
          --arg system '${system}' \
          --argjson expected '${builtins.toJSON (builtins.attrNames nativeTriggerDefinitions)}' \
          --argjson expectedApplications '${builtins.toJSON (builtins.attrNames nativeApplicationDefinitions)}' \
          '.schema == "focaccia-evaluation-config-v5" and
           .role == "native" and
           .system == $system and
           (.triggers | keys) == $expected and
           (.applications | keys) == $expectedApplications and
           (.emulators | type) == "object" and
           (.emulatorCases | type) == "object"' \
          ${nativeEvaluationConfig} > "$TMPDIR/config.json"
        touch "$out"
      '';
  incrementalEvaluationCompositionCheck =
    pkgs.runCommand "incremental-evaluation-composition"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_native_runs_append_disjoint_cases_and_reject_reruns \
            test_evaluation.EvaluationTests.test_emulated_runs_append_disjoint_cases
        )
        touch "$out"
      '';
  wholeProgramAcceptanceCheck = (mkIdentityFixtureCheck "whole-program-without-witness-stop-pc" [
    "test_whole_program_completion_without_witness_stop_pc"
    "test_full_application_requires_completion_before_timings"
    "test_reference_acceptance_requires_complete_terminal_trace"
  ]).overrideAttrs (old: {
    buildCommand = old.buildCommand + ''
      # Reintroduce the live regression in the disposable build copy only.
      chmod u+w evaluation.py
      python - <<'PY'
      from pathlib import Path
      path = Path("evaluation.py")
      source = path.read_text()
      original = "# use experiment execution evidence to turn semantic gaps into completion.\n    _require_complete_trace(report)"
      mutant = "# use experiment execution evidence to turn semantic gaps into completion.\n    _require_complete_terminal_trace(report)"
      assert source.count(original) == 1
      path.write_text(source.replace(original, mutant))
      PY
      if python -B -m unittest -v test_evaluation.EvaluationTests.test_whole_program_completion_without_witness_stop_pc; then
        echo 'Whole-program stop-PC regression survived' >&2
        exit 1
      fi
    '';
  });
  unannotatedTriggerFixture = import ./mk-trigger.nix {
    inherit pkgs;
    trigger = {
      id = "unannotated-fixture";
      guestIsa = if system == "aarch64-linux" then "aarch64" else "x86_64";
      source = pkgs.writeTextDir "main.c" ''
        int main(void) { volatile unsigned value = 7; return value != 7; }
      '';
      sources = [ "main.c" ];
      cflags = [ ];
      freestanding = false;
      instruction = "unannotated ordinary C program";
    };
  };
  markerFreeTriggerWholeProgramCheck = assert qemuEvaluationData.triggerTraceMode == "whole-program";
    (mkIdentityFixtureCheck "marker-free-trigger-whole-program" [
    "test_marker_free_trigger_capture_uses_whole_program"
    "test_marker_free_trigger_consumer_rejects_truncated_and_legacy"
  ]).overrideAttrs (old: {
    buildCommand = ''
      ${pkgs.binutils}/bin/nm ${unannotatedTriggerFixture}/bin/reproducer-unannotated-fixture > symbols
      if ${pkgs.gnugrep}/bin/grep -E 'focaccia_trace_(start|stop)' symbols; then
        echo 'Unannotated fixture unexpectedly has witness markers' >&2
        exit 1
      fi
    '' + old.buildCommand;
  });
  fullApplicationCompletionCheck = mkIdentityFixtureCheck "full-application-completion" [
    "test_full_application_requires_completion_before_timings"
    "test_full_curl_records_cross_validated_and_speculative_profiles"
    "test_native_selective_application_records_rr_and_uses_main_bound"
    "test_qemu_application_role_replays_bound_native_artifacts"
  ];
  evaluationFullCurlModesCheck =
    pkgs.runCommand "full-curl-measurement-modes"
      {
        nativeBuildInputs = [
          pkgs.jq
          pkgs.python3
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_full_curl_records_cross_validated_and_speculative_profiles
        )
        ${
          if system == "x86_64-linux" then
            ''
              jq -e '
                .role == "native" and
                (.applications | keys) == ["curl-full"] and
                .applications["curl-full"].traceMode == "full"
              ' ${nativeFullCurlEvaluationConfig} >/dev/null
            ''
          else
            ''
              jq -e '
                .role == "qemu" and
                (.emulatorCases | keys) == ["qemu-app-curl-full"] and
                .emulatorCases["qemu-app-curl-full"].trigger == "curl-full" and
                .emulatorCases["qemu-app-curl-full"].traceMode == "full" and
                .emulators["qemu-8-2-0"].backend == "qemu-gdb"
              ' ${qemuFullCurlEvaluationConfig} >/dev/null
            ''
        }
        touch "$out"
      '';
  fakeQemuEvaluationRunner = pkgs.writeShellScriptBin "evaluate-qemu" ''
    [ "$#" -eq 4 ] || exit 90
    [ "$1" = --input ] || exit 91
    [ "$3" = --iterations ] || exit 92
    printf 'qemu|%s|%s\n' "$2" "$4" >> "$EVALUATOR_STAGE_LOG"
    exit "''${EVALUATOR_QEMU_STATUS:-0}"
  '';
  fakeReproducerEvaluationRunner = pkgs.writeShellScriptBin "evaluate-reproducers" ''
    [ "$#" -eq 4 ] || exit 90
    [ "$1" = --input ] || exit 91
    [ "$3" = --iterations ] || exit 92
    printf 'qemu-reproducers|%s|%s\n' \
      "$2" "$4" >> "$EVALUATOR_STAGE_LOG"
    exit "''${EVALUATOR_REPRODUCER_STATUS:-0}"
  '';
  fakeBox64EvaluationRunner = pkgs.writeShellScriptBin "evaluate-box64" ''
    [ "$#" -eq 4 ] || exit 90
    [ "$1" = --input ] || exit 91
    [ "$3" = --iterations ] || exit 92
    printf 'box64|%s|%s\n' "$2" "$4" >> "$EVALUATOR_STAGE_LOG"
    exit "''${EVALUATOR_BOX64_STATUS:-0}"
  '';
  fakeFullCurlEvaluationRunner = pkgs.writeShellScriptBin "evaluate-qemu-curl-full" ''
    [ "$#" -eq 4 ] || exit 90
    [ "$1" = --input ] || exit 91
    [ "$3" = --iterations ] || exit 92
    printf 'qemu-full-curl|%s|%s\n' \
      "$2" "$4" >> "$EVALUATOR_STAGE_LOG"
    exit "''${EVALUATOR_FULL_CURL_STATUS:-0}"
  '';
  emulatorEvaluationTestStages = [
    {
      label = "QEMU";
      testName = "qemu";
      program = "${fakeQemuEvaluationRunner}/bin/evaluate-qemu";
    }
  ]
  ++ lib.optionals (system == "aarch64-linux") [
    {
      label = "QEMU reproducer effectiveness";
      testName = "qemu-reproducers";
      program = "${fakeReproducerEvaluationRunner}/bin/evaluate-reproducers";
    }
    {
      label = "Box64";
      testName = "box64";
      program = "${fakeBox64EvaluationRunner}/bin/evaluate-box64";
    }
    {
      label = "QEMU full Curl";
      testName = "qemu-full-curl";
      program = "${fakeFullCurlEvaluationRunner}/bin/evaluate-qemu-curl-full";
    }
  ];
  emulatorEvaluationTestRunner = mkEmulatorEvaluationRunner "evaluate-emulator" emulatorEvaluationTestStages;
  emulatorEvaluationDispatchCheck =
    pkgs.runCommand "emulator-evaluation-dispatch"
      {
        nativeBuildInputs = [
          pkgs.diffutils
          pkgs.gnugrep
        ];
      }
      ''
        export EVALUATOR_STAGE_LOG="$TMPDIR/stages.log"
        run_root="$TMPDIR/run root"
        runner=${emulatorEvaluationTestRunner}/bin/evaluate-emulator

        "$runner" --input "$run_root" --iterations 3 >passed.log
        cat >expected.log <<EOF
        ${lib.concatMapStringsSep "\n" (
          stage: "${stage.testName}|$run_root|3"
        ) emulatorEvaluationTestStages}
        EOF
        diff -u expected.log "$EVALUATOR_STAGE_LOG"

        : > "$EVALUATOR_STAGE_LOG"
        set +e
        EVALUATOR_QEMU_STATUS=7 \
          "$runner" --input="$run_root" --iterations=2 \
          >failed.log 2>&1
        status=$?
        set -e
        test "$status" -eq 1
        cat >expected-failure.log <<EOF
        ${lib.concatMapStringsSep "\n" (
          stage: "${stage.testName}|$run_root|2"
        ) emulatorEvaluationTestStages}
        EOF
        diff -u expected-failure.log "$EVALUATOR_STAGE_LOG"

        : > "$EVALUATOR_STAGE_LOG"
        set +e
        EVALUATOR_QEMU_STATUS=130 \
          "$runner" --input "$run_root" >interrupted.log 2>&1
        status=$?
        set -e
        test "$status" -eq 130
        printf 'qemu|%s|1\n' "$run_root" >expected-interrupted.log
        diff -u expected-interrupted.log "$EVALUATOR_STAGE_LOG"

        : > "$EVALUATOR_STAGE_LOG"
        set +e
        "$runner" --input "$run_root" --case 508 >invalid.log 2>&1
        status=$?
        set -e
        test "$status" -eq 2
        test ! -s "$EVALUATOR_STAGE_LOG"

        "$runner" --help >help.log
        grep -F -- 'Stages on ${system}:' help.log
        touch "$out"
      '';
  reproducerEffectivenessEvaluationCheck =
    pkgs.runCommand "reproducer-effectiveness-evaluation" { }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/reproducer_evaluation.py} \
          evaluation/reproducer_evaluation.py
        cp ${../evaluation/test_reproducer_evaluation.py} \
          evaluation/test_reproducer_evaluation.py
        (
          cd evaluation
          ${focaccia.packages.${system}.focaccia}/bin/python3.12 \
            -m unittest -v test_reproducer_evaluation
        )
        touch "$out"
      '';
  evaluationCaptureTimeoutCheck =
    pkgs.runCommand "evaluation-capture-timeout"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_native_capture_timeout_allows_large_trace_serialization \
            test_evaluation.EvaluationTests.test_run_process_uses_requested_timeout
        )
        touch "$out"
      '';
  evaluationMsgpackDefaultCheck =
    pkgs.runCommand "evaluation-msgpack-default"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_native_trace_format_defaults_to_msgpack \
            test_evaluation.EvaluationTests.test_native_role_collects_baseline_trace_and_component_times \
            test_evaluation.EvaluationTests.test_native_selective_application_records_rr_and_uses_main_bound
        )
        touch "$out"
      '';
  evaluationPersistenceTimingCheck =
    pkgs.runCommand "profile-total-excludes-serialization"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_component_timings_require_complete_profile \
            test_evaluation.EvaluationTests.test_native_role_collects_baseline_trace_and_component_times \
            test_evaluation.EvaluationTests.test_native_selective_application_records_rr_and_uses_main_bound
        )
        touch "$out"
      '';
  evaluationProfileReportCheck =
    pkgs.runCommand "profile-report-timings"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_component_timings_require_complete_profile \
            test_evaluation.EvaluationTests.test_native_role_collects_baseline_trace_and_component_times \
            test_evaluation.EvaluationTests.test_native_selective_application_records_rr_and_uses_main_bound
        )
        touch "$out"
      '';
  evaluationTriggerBoundsCheck =
    pkgs.runCommand "evaluation-trigger-bounds"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_native_role_collects_baseline_trace_and_component_times
        )
        touch "$out"
      '';
  evaluationOfflineValidationCheck =
    pkgs.runCommand "evaluation-offline-log-validation"
      {
        nativeBuildInputs = [ focaccia.packages.${system}.focaccia ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/offline_validation.py} evaluation/offline_validation.py
        cp ${../evaluation/test_offline_validation.py} evaluation/test_offline_validation.py
        (
          cd evaluation
          python -m unittest -v test_offline_validation.py
          python offline_validation.py --help > "$TMPDIR/help.txt"
        )
        grep -F -- '--backend' "$TMPDIR/help.txt"
        grep -F -- 'box64' "$TMPDIR/help.txt"
        grep -F -- 'arancini' "$TMPDIR/help.txt"
        touch "$out"
      '';
  preRealizedEmulatorCheck =
    pkgs.runCommand "pre-realized-emulator-outputs"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_emulator_output_must_be_pre_realized
        )
        touch "$out"
      '';
  evaluationEmulatorTraceFormatCheck =
    pkgs.runCommand "evaluation-emulator-trace-format"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_box64_whole_program_binds_process_completion_and_structured_report \
            test_evaluation.EvaluationTests.test_qemu_emulated_role_launches_gdb_driver_and_checks_report
        )
        touch "$out"
      '';
  evaluationQemuDriverCheck =
    pkgs.runCommand "evaluation-qemu-driver"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_qemu_emulated_role_launches_gdb_driver_and_checks_report
        )
        touch "$out"
      '';
  exactGuestSignalLocalizationCheck =
    assert
      system != "aarch64-linux"
      || (
        qemuCaseEvaluationData."qemu-1376".emulatorCases."qemu-1376".expectedTerminalSignal == "SIGSEGV"
        && qemuCaseEvaluationData."qemu-1377".emulatorCases."qemu-1377".expectedTerminalSignal == "SIGSEGV"
        &&
          qemuCaseEvaluationData."qemu-1832422".emulatorCases."qemu-1832422".expectedTerminalSignal
          == "SIGILL"
      );
    pkgs.runCommand "exact-guest-signal-localization"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          ruff check evaluation.py test_evaluation.py
          ruff format --check evaluation.py test_evaluation.py
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_crash_mismatch_requires_exact_signal_and_fault_pc
        )
        touch "$out"
      '';
  terminalValidationCutpointCheck =
    assert
      system != "aarch64-linux"
      || qemuCaseEvaluationData."qemu-1861404".emulatorCases."qemu-1861404".validationCutpoint == "stop";
    pkgs.runCommand "terminal-validation-cutpoint"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          ruff check evaluation.py test_evaluation.py
          ruff format --check evaluation.py test_evaluation.py
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_qemu_emulated_role_launches_gdb_driver_and_checks_report
        )
        touch "$out"
      '';
  unmatchedTransformSkippingCheck =
    pkgs.runCommand "opt-in-unmatched-transform-skipping"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          ruff check evaluation.py test_evaluation.py
          ruff format --check evaluation.py test_evaluation.py
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_unmatched_skipping_is_explicitly_opt_in \
            test_evaluation.EvaluationTests.test_qemu_application_role_replays_bound_native_artifacts
        )
        touch "$out"
      '';
  triggerMismatchContracts = lib.mapAttrs (_: data: builtins.head (builtins.attrValues data.emulatorCases)) (
    lib.filterAttrs (_: data: (builtins.head (builtins.attrValues data.emulatorCases)) ? expectedMismatchCode) qemuCaseEvaluationData
  );
  exactTriggerMismatchLocalizationCheck =
    pkgs.runCommand "exact-trigger-mismatch-localization"
      { nativeBuildInputs = [ pkgs.python3 pkgs.ruff ]; }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        cd evaluation
        ruff check evaluation.py test_evaluation.py
        ruff format --check evaluation.py test_evaluation.py
        python -m unittest -v \
          test_evaluation.EvaluationTests.test_trigger_mismatch_contract_rejects_missing_and_invalid_fields \
          test_evaluation.EvaluationTests.test_trigger_mismatch_rejects_address_overflow_before_qemu \
          test_evaluation.EvaluationTests.test_trigger_mismatch_requires_exact_localization_before_timings \
          test_evaluation.EvaluationTests.test_trigger_memory_mismatch_requires_structured_address \
          test_evaluation.EvaluationTests.test_trigger_reference_requires_terminal_completion_before_timings \
          test_evaluation.EvaluationTests.test_qemu_emulated_role_launches_gdb_driver_and_checks_report
        touch "$out"
      '';
  triggerMismatchWitnessBoundariesCheck =
    let
      witnesses = lib.mapAttrs (_: case:
        let
          cross = if case.guestSystem == "x86_64-linux" then pkgs.pkgsCross.musl64 else pkgs.pkgsCross.aarch64-multiplatform-musl;
        in case // {
          binary = "${triggerPackages.${case.trigger}}/bin/reproducer-${case.trigger}";
          objdump = "${cross.stdenv.cc.bintools}/bin/${cross.stdenv.cc.targetPrefix}objdump";
        }
      ) triggerMismatchContracts;
      config = pkgs.writeText "trigger-mismatch-witnesses.json" (builtins.toJSON witnesses);
    in pkgs.runCommand "trigger-mismatch-witness-boundaries" { nativeBuildInputs = [ pkgs.python3 ]; } ''
      python ${../evaluation/check_trigger_boundaries.py} ${config}
      touch "$out"
    '';
  exactApplicationMismatchLocalizationCheck =
    pkgs.runCommand "exact-application-mismatch-localization"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          ruff check evaluation.py test_evaluation.py
          ruff format --check evaluation.py test_evaluation.py
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_application_mismatch_requires_exact_localized_classification \
            test_evaluation.EvaluationTests.test_qemu_application_role_replays_bound_native_artifacts
        )
        touch "$out"
      '';
  referenceTerminalAcceptanceCheck =
    pkgs.runCommand "reference-terminal-acceptance"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          ruff check evaluation.py test_evaluation.py
          ruff format --check evaluation.py test_evaluation.py
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_reference_acceptance_requires_complete_terminal_trace
        )
        touch "$out"
      '';
  # Shape-only checks must not realize the emulator paths encoded in this JSON.
  # Production runners retain the original, context-bearing configuration.
  qemuCheckConfigurationJSON = builtins.unsafeDiscardStringContext (
    builtins.toJSON qemuEvaluationData
  );
  qemuCheckConfiguration =
    assert !builtins.hasContext qemuCheckConfigurationJSON;
    pkgs.writeText "qemu-check-configuration.json" qemuCheckConfigurationJSON;
  qemuCheckConfigurationIsolationCheck =
    assert !builtins.hasContext qemuCheckConfigurationJSON;
    pkgs.runCommand "qemu-check-configuration-isolation" { nativeBuildInputs = [ pkgs.jq ]; } ''
      jq -e '
        type == "object" and
        (.emulatorCases | type == "object") and
        (.emulators | type == "object")
      ' ${qemuCheckConfiguration} > /dev/null
      ${lib.optionalString (system == "aarch64-linux") ''
        jq -e '
          ([.emulatorCases[] | select(.kind == "application")] | length) == 3 and
          ([.emulatorCases[] | select(.kind == "application") | .trigger] | unique | sort) == ["curl", "lua", "sqlite"] and
          ([.emulatorCases[] | select(.kind == "application" and .expectedValidation == "mismatch")] | length) == 3 and
          ([.emulatorCases[] | select(.expectedValidation == "accepted")] | length) == 0 and
          ([.emulatorCases | keys[] | select(endswith("-reference"))] | length) == 0 and
          ([.emulators | keys[] | select(endswith("-reference"))] | length) == 0
        ' ${qemuCheckConfiguration} > /dev/null
      ''}
      touch "$out"
    '';
  qemuApplicationReplayCheck =
    pkgs.runCommand "qemu-application-deterministic-replay"
      {
        nativeBuildInputs = [
          focaccia.packages.${system}.focaccia
          pkgs.jq
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/replay_manifest.py} evaluation/replay_manifest.py
        cp ${../evaluation/replay_preflight.py} evaluation/replay_preflight.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        cp ${../evaluation/test_replay_preflight.py} evaluation/test_replay_preflight.py
        (
          cd evaluation
          ruff check evaluation.py replay_manifest.py replay_preflight.py test_evaluation.py test_replay_preflight.py
          ruff format --check evaluation.py replay_manifest.py replay_preflight.py test_evaluation.py test_replay_preflight.py
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_qemu_application_role_replays_bound_native_artifacts \
            test_evaluation.EvaluationTests.test_qemu_application_recreates_recorded_workload_interfaces \
            test_evaluation.EvaluationTests.test_qemu_application_rejects_inactive_or_failed_replay_coverage \
            test_replay_preflight
          python replay_manifest.py --help > "$TMPDIR/manifest-help.txt"
          python replay_preflight.py --help > "$TMPDIR/preflight-help.txt"
        )
        grep -F -- '--deterministic-log' "$TMPDIR/manifest-help.txt"
        grep -F -- '--deterministic-log' "$TMPDIR/preflight-help.txt"
        test -e ${qemuCheckConfigurationIsolationCheck}
        touch "$out"
      '';
  luaSignalReadinessCheck = lib.optionalAttrs (system == "x86_64-linux") {
    lua-signal-readiness = pkgs.runCommand "lua-signal-readiness" { } ''
      log="$TMPDIR/lua.log"
      input="$TMPDIR/lua.stdin"
      mkfifo "$input"
      exec 3<>"$input"
      ${applicationOutputs.packages."application-lua"}/bin/lua \
        ${
          applicationOutputs.packages."application-workloads"
        }/share/focaccia-evaluation/workloads/lua.lua \
        <"$input" >"$log" 2>&1 &
      pid=$!
      trap 'kill -KILL "$pid" 2>/dev/null || true' EXIT

      ready=0
      for _ in $(seq 1 5000); do
        if test -s "$log"; then
          ready=1
          break
        fi
        sleep 0.001
      done
      test "$ready" -eq 1
      kill -INT "$pid"

      exited=0
      for _ in $(seq 1 5000); do
        if ! kill -0 "$pid" 2>/dev/null; then
          exited=1
          break
        fi
        sleep 0.001
      done
      test "$exited" -eq 1
      set +e
      wait "$pid"
      status=$?
      set -e
      test "$status" -eq 1
      grep -F 'fib(30) =' "$log"
      grep -F 'interrupted!' "$log"
      trap - EXIT
      touch "$out"
    '';
  };
  evaluationQemuPluginDriverCheck =
    pkgs.runCommand "qemu-plugin-terminal-evidence-handshake"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.ruff
        ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          ruff check evaluation.py test_evaluation.py
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_qemu_plugin_role_requires_complete_localized_mismatch \
            test_evaluation.EvaluationTests.test_qemu_emulated_role_launches_gdb_driver_and_checks_report \
            test_evaluation.EvaluationTests.test_qemu_application_role_replays_bound_native_artifacts
        )
        touch "$out"
      '';
  nativeWitnessIdentityCheck =
    pkgs.runCommand "native-witness-identity" { nativeBuildInputs = [ pkgs.python3 ]; }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_qemu_plugin_role_rejects_obsolete_native_binary
        )
        touch "$out"
      '';
  box64WholeProgramCompletionCheck =
    pkgs.runCommand "box64-whole-program-completion"
      {
        nativeBuildInputs = [ pkgs.python3 focaccia.packages.${system}.focaccia ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/offline_validation.py} evaluation/offline_validation.py
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_offline_validation.py} evaluation/test_offline_validation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_offline_validation.OfflineValidationTests.test_box64_log_is_validated_with_oracle_guest_architecture \
            test_evaluation.EvaluationTests.test_box64_whole_program_binds_process_completion_and_structured_report
        )
        touch "$out"
      '';
  evaluationBox64DriverCheck =
    pkgs.runCommand "evaluation-box64-driver"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        mkdir evaluation
        cp ${../evaluation/evaluation.py} evaluation/evaluation.py
        cp ${../evaluation/test_evaluation.py} evaluation/test_evaluation.py
        (
          cd evaluation
          python -m unittest -v \
            test_evaluation.EvaluationTests.test_box64_whole_program_binds_process_completion_and_structured_report
        )
        touch "$out"
      '';
in
{
  inherit
    codeNamingPolicyCheck
    nativeOracleIdentityCheck
    nativeTriggerGdbserverCheck
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
}
