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
    export MPLBACKEND=Agg
    exec ${python}/bin/python ${../evaluation/plots.py} "$@"
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
        ${python}/bin/python ${../evaluation/plots.py} \
          --input fixture \
          --output figures \
          --reproducer-sizes fixture/reproducer-sizes.json

        destination="$out/share/focaccia-evaluation/figures"
        mkdir -p "$destination"
        for figure in \
          split-overhead-breakdown.pdf \
          tracing-comparison.pdf \
          realworld-split-overhead-breakdown.pdf \
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
        ${python}/bin/python ${../evaluation/plots.py} \
          --input fixture \
          --output invalid-figures \
          --reproducer-sizes fixture/reproducer-sizes.json \
          >invalid.log 2>&1
        test ! -e invalid-figures/split-overhead-breakdown.pdf
        test ! -e invalid-figures/reproducer-code-size.pdf
        grep -F 'failed provenance' invalid.log

        mkdir empty empty-figures
        touch empty-figures/split-overhead-breakdown.pdf
        ${python}/bin/python ${../evaluation/plots.py} \
          --input empty --output empty-figures >empty.log 2>&1
        test -s empty-figures/combined-bug-study.pdf
        test "$(find empty-figures -type f -printf '%f\n')" = \
          combined-bug-study.pdf
        grep -F 'no evaluator results found' empty.log
      '';
in
{
  inherit
    fontsConf
    package
    python
    runner
    ;
}
