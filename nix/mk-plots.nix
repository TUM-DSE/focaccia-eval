{ pkgs }:

let
  python = pkgs.python3.withPackages (pythonPackages: [
    pythonPackages.matplotlib
    pythonPackages.numpy
    pythonPackages.seaborn
  ]);
  fontsConf = pkgs.makeFontsConf {
    fontDirectories = [ pkgs.libertine ];
  };
  x86PlotGuestCompiler = pkgs.pkgsCross.gnu64.stdenv.cc;
  x86PlotGuest = pkgs.runCommand "focaccia-plot-full-curl-guest" { } ''
    mkdir -p "$out/bin"
    ${x86PlotGuestCompiler}/bin/${x86PlotGuestCompiler.targetPrefix}cc \
      -nostdlib -no-pie -Wl,-e,_start -Wl,--build-id=none \
      ${../evaluation/fixtures/plots/cross-isa-full-curl-guest.S} \
      -o "$out/bin/application-curl-full-injected"
    ${pkgs.binutils}/bin/nm "$out/bin/application-curl-full-injected" > symbols.txt
    grep -Eq '[[:space:]][Tt][[:space:]]+focaccia_injection_curl_2175$' symbols.txt
    grep -Eq '[[:space:]][Tt][[:space:]]+focaccia_trace_stop_curl$' symbols.txt
  '';
  runner = pkgs.writeShellScriptBin "plot-evaluation" ''
    export FONTCONFIG_FILE=${fontsConf}
    export PATH=${pkgs.fontconfig}/bin:${pkgs.binutils}/bin:$PATH
    export MPLBACKEND=Agg
    font_cache="$(${pkgs.coreutils}/bin/mktemp -d)"
    export MPLCONFIGDIR="$font_cache"
    trap '${pkgs.coreutils}/bin/rm -rf "$font_cache"' EXIT
    ${python}/bin/python ${../evaluation}/plots.py "$@"
  '';
  fontDiscoveryCheck = pkgs.runCommand "nix-plot-font-discovery"
    { nativeBuildInputs = [ python pkgs.poppler-utils ]; }
    ''
      export HOME="$TMPDIR"
      export MPLCONFIGDIR="$TMPDIR/empty-font-cache"
      mkdir empty
      PATH=/nonexistent ${runner}/bin/plot-evaluation --input empty --output figures
      pdffonts figures/combined-bug-study.pdf > fonts.txt
      python - <<'PY'
      from pathlib import Path

      font_rows = Path("fonts.txt").read_text().splitlines()[2:]
      font_names = [row.split()[0] for row in font_rows if row.strip()]
      assert any("LinLibertine" in name for name in font_names), font_names
      assert not any("DejaVu" in name for name in font_names), font_names
      PY
      mkdir "$out"
      cp fonts.txt figures/combined-bug-study.pdf "$out/"
    '';
  selectiveApplicationAcceptanceCheck = pkgs.runCommand "selective-application-acceptance"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp -R ${../evaluation} evaluation
      chmod -R u+w evaluation
      cd evaluation
      ruff check evaluation.py test_selective_acceptance.py
      ruff format --check evaluation.py test_selective_acceptance.py
      python -m unittest -v test_selective_acceptance
      touch "$out"
    '';
  wholeRunExperimentExecutionCheck = pkgs.runCommand "whole-run-experiment-execution"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp -R ${../evaluation} evaluation
      chmod -R u+w evaluation
      cd evaluation
      ruff check evaluation.py test_selective_acceptance.py
      ruff format --check evaluation.py test_selective_acceptance.py
      python -m unittest -v \
        test_selective_acceptance.SelectiveAcceptanceTests.test_whole_run_execution_is_separate_from_semantic_completion \
        test_selective_acceptance.SelectiveAcceptanceTests.test_whole_run_execution_rejects_abort_unknown_terminal_and_missing_bug \
        test_selective_acceptance.SelectiveAcceptanceTests.test_whole_run_expected_signal_is_independent_terminal_evidence
      touch "$out"
    '';
  fatalDiagnosticEligibilityCheck = pkgs.runCommand "fatal-diagnostic-eligibility"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp -R ${../evaluation} evaluation
      chmod -R u+w evaluation
      cd evaluation
      ruff check diagnostic_partial.py test_diagnostic_partial.py
      ruff format --check diagnostic_partial.py test_diagnostic_partial.py
      python -m unittest -v test_diagnostic_partial
      touch "$out"
    '';

  sizeMeasurementCheck = pkgs.runCommand "reproducer-size-measurement-fidelity"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp ${../evaluation/plots.py} plots.py
      cp ${../evaluation/test_plots.py} test_plots.py
      ruff check test_plots.py
      ruff format --check test_plots.py
      cp ${../evaluation/evaluation.py} evaluation.py
      python -m unittest -v test_plots
      touch "$out"
    '';
  applicationTrendRatiosCheck = pkgs.runCommand "application-trend-ratio-normalization"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp ${../evaluation/plots.py} plots.py
      cp ${../evaluation/test_plots.py} test_plots.py
      cp ${../evaluation/evaluation.py} evaluation.py
      ruff check plots.py test_plots.py
      ruff format --check plots.py test_plots.py
      python -m unittest -v test_plots.ApplicationTrendPlotTests
      touch "$out"
    '';
  profileRelocationCheck = pkgs.runCommand "explicit-profile-relocation"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp ${../evaluation/plots.py} plots.py
      cp ${../evaluation/test_plots.py} test_plots.py
      ruff check test_plots.py
      ruff format --check test_plots.py
      cp ${../evaluation/evaluation.py} evaluation.py
      python -m unittest -v test_plots.ProfileRelocationTests
      touch "$out"
    '';
  timingAccountingCheck = pkgs.runCommand "exclusive-and-end-to-end-timing-accounting"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp ${../evaluation/plots.py} plots.py
      cp ${../evaluation/test_plots.py} test_plots.py
      cp ${../evaluation/evaluation.py} evaluation.py
      ruff check plots.py test_plots.py
      ruff format --check plots.py test_plots.py
      python -m unittest -v test_plots.TimingAccountingTests
      touch "$out"
    '';
  hostMeasurementIdentityCheck = pkgs.runCommand "host-separated-measurement-identity"
    { nativeBuildInputs = [ python pkgs.ruff ]; }
    ''
      export HOME="$TMPDIR"
      export MPLBACKEND=Agg
      cp ${../evaluation/plots.py} plots.py
      cp ${../evaluation/test_plots.py} test_plots.py
      ruff check test_plots.py
      ruff format --check test_plots.py
      cp ${../evaluation/evaluation.py} evaluation.py
      python -m unittest -v test_plots.HostMeasurementIdentityTests
      touch "$out"
    '';
  multiHostEvaluationPlotWorkflowCheck =
    pkgs.runCommand "multi-host-evaluation-plot-workflow"
      { nativeBuildInputs = [ python pkgs.ruff ]; }
      ''
        export HOME="$TMPDIR"
        export MPLBACKEND=Agg
        cp ${../evaluation/plots.py} plots.py
        cp ${../evaluation/test_plots.py} test_plots.py
        cp ${../evaluation/evaluation.py} evaluation.py
        ruff check plots.py test_plots.py
        ruff format --check plots.py test_plots.py
        python -m unittest -v \
          test_plots.HostMeasurementIdentityTests.test_cli_never_merges_disjoint_host_role_rows \
          test_plots.HostMeasurementIdentityTests.test_cli_separates_multi_host_figures_and_measurements
        touch "$out"
      '';
  crossIsaFullCurlRolePairingCheck =
    pkgs.runCommand "cross-isa-full-curl-role-pairing"
      { nativeBuildInputs = [ python pkgs.ruff pkgs.binutils ]; }
      ''
        export HOME="$TMPDIR"
        export FONTCONFIG_FILE=${fontsConf}
        export MPLBACKEND=Agg
        cp ${../evaluation/plots.py} plots.py
        cp ${../evaluation/test_plots.py} test_plots.py
        cp ${../evaluation/evaluation.py} evaluation.py
        ruff check plots.py test_plots.py
        ruff format --check plots.py test_plots.py
        python -m unittest -v test_plots.CrossIsaFullCurlPlotTests
        touch "$out"
      '';
  crossIsaSelectiveApplicationRolePairingCheck =
    pkgs.runCommand "cross-isa-selective-application-role-pairing"
      {
        nativeBuildInputs = [ python pkgs.binutils ];
        FONTCONFIG_FILE = fontsConf;
      }
      ''
        export HOME="$TMPDIR"
        export MPLBACKEND=Agg
        cp -R ${../evaluation/fixtures/plots} fixture
        chmod -R u+w fixture
        ${python}/bin/python \
          ${../evaluation/fixtures/plots/prepare_cross_isa_full_curl.py} \
          fixture ${x86PlotGuest}/bin/application-curl-full-injected
        mkdir figures
        ${python}/bin/python ${../evaluation}/plots.py \
          --input fixture --output figures \
          --reproducer-sizes fixture/reproducer-sizes.json
        python - <<'PY'
        import json
        from pathlib import Path

        pairing = json.loads(Path("figures/selective-application-role-pairing.json").read_text())
        assert pairing["schema"] == "focaccia-cross-isa-selective-applications-role-pair-v1"
        assert set(pairing["applications"]) == {"curl", "lua", "sqlite"}
        for application, evidence in pairing["applications"].items():
            assert evidence["emulator"] in {"qemu-8-2-0", "qemu-9-0-0", "qemu-6-1-0"}
            assert len(evidence["iterations"]) == 1
            iteration = evidence["iterations"][0]
            for field in ("guestBinarySha256", "workloadSha256", "oracleSha256", "runManifestSha256", "validationReportSha256", "nativeProfileSha256", "qemuProfileSha256"):
                assert len(iteration[field]) == 64, (application, field)
        for name in ("realworld-split-overhead-breakdown.pdf", "application-trend-ratios.pdf"):
            assert Path("figures", name).read_bytes().startswith(b"%PDF")
        PY
        touch "$out"
      '';
  package =
    pkgs.runCommand "focaccia-evaluation-plots"
      {
        nativeBuildInputs = [
          pkgs.binutils
          pkgs.fontconfig
          python
        ];
        FONTCONFIG_FILE = fontsConf;
      }
      ''
        export HOME="$TMPDIR"
        export MPLBACKEND=Agg
        ${python}/bin/python - <<'PY'
        from matplotlib import font_manager

        font_manager.findfont("Linux Libertine O", fallback_to_default=False)
        PY
        cp -R ${../evaluation/fixtures/plots} fixture
        chmod -R u+w fixture
        ${python}/bin/python \
          ${../evaluation/fixtures/plots/prepare_cross_isa_full_curl.py} \
          fixture ${x86PlotGuest}/bin/application-curl-full-injected
        mkdir figures
        ${python}/bin/python ${../evaluation}/plots.py \
          --input fixture \
          --output figures \
          --reproducer-sizes fixture/reproducer-sizes.json

        test -s figures/tracing-comparison.pdf
        test -s figures/full-curl-role-pairing.json
        test -s figures/multi-host-summary.json
        test -s figures/aarch64-linux/combined-bug-study.pdf
        test -s figures/x86_64-linux/combined-bug-study.pdf
        destination="$out/share/focaccia-evaluation/figures"
        mkdir -p "$destination"
        cp figures/tracing-comparison.pdf figures/full-curl-role-pairing.json \
          figures/multi-host-summary.json "$destination/"
        for system in aarch64-linux x86_64-linux; do
          mkdir -p "$destination/$system"
          cp "figures/$system/combined-bug-study.pdf" "$destination/$system/"
        done

        printf 'corrupt\n' >> \
          fixture/emulated/qemu/aarch64-linux/profiles/trigger.json
        printf 'corrupt\n' >> fixture/size-evidence/minimized-1372.bin
        mkdir invalid-figures
        ${python}/bin/python ${../evaluation}/plots.py \
          --input fixture \
          --output invalid-figures \
          --reproducer-sizes fixture/reproducer-sizes.json \
          >invalid.log 2>&1
        # Partial trigger figures may still contain independently verified cases;
        # corrupting one profile must omit that sample, not erase valid samples.
        grep -F 'failed provenance' invalid.log
        grep -F 'trigger overhead omits incomplete cases' invalid.log
        grep -F 'reproducer size figure omits incomplete cases' invalid.log

        mkdir empty empty-figures
        touch empty-figures/split-overhead-breakdown.pdf
        ${python}/bin/python ${../evaluation}/plots.py \
          --input empty --output empty-figures >empty.log 2>&1
        test -s empty-figures/combined-bug-study.pdf
        test "$(find empty-figures -type f -printf '%f\n' | sort)" = \
          $'combined-bug-study.pdf\ntiming-accounting.json'
        grep -F 'no evaluator results found' empty.log
      '';
in
{
  inherit
    applicationTrendRatiosCheck
    fontsConf
    fontDiscoveryCheck
    fatalDiagnosticEligibilityCheck
    package
    python
    runner
    sizeMeasurementCheck
    profileRelocationCheck
    hostMeasurementIdentityCheck
    multiHostEvaluationPlotWorkflowCheck
    crossIsaFullCurlRolePairingCheck
    crossIsaSelectiveApplicationRolePairingCheck
    timingAccountingCheck
    selectiveApplicationAcceptanceCheck
    wholeRunExperimentExecutionCheck
    ;
}
