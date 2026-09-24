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
          test_plots.HostMeasurementIdentityTests.test_cli_separates_multi_host_figures_and_measurements
        touch "$out"
      '';
  package =
    pkgs.runCommand "focaccia-evaluation-plots"
      {
        nativeBuildInputs = [
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
        mkdir figures
        ${python}/bin/python ${../evaluation}/plots.py \
          --input fixture \
          --output figures \
          --reproducer-sizes fixture/reproducer-sizes.json

        destination="$out/share/focaccia-evaluation/figures"
        mkdir -p "$destination"
        for figure in \
          split-overhead-breakdown.pdf \
          tracing-comparison.pdf \
          realworld-split-overhead-breakdown.pdf \
          application-trend-ratios.pdf \
          reproducer-code-size.pdf \
          combined-bug-study.pdf
        do
          test -s "figures/$figure"
          cp "figures/$figure" "$destination/"
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
    timingAccountingCheck
    selectiveApplicationAcceptanceCheck
    wholeRunExperimentExecutionCheck
    ;
}
