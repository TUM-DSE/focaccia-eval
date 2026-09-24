{
  pkgs,
  nix2container,
  dependencyPackages,
  self,
  focaccia,
  system,
  fontsConf,
  commandPackages,
  commandNames,
}:

let
  lib = pkgs.lib;
  tag = if self ? shortRev then self.shortRev else "dirty";
  stablePackages = [
    pkgs.bashInteractive
    pkgs.coreutils
    pkgs.findutils
    pkgs.fontconfig
    pkgs.gnugrep
    pkgs.gnused
    pkgs.jq
    pkgs.libertine
  ];
  environment = pkgs.buildEnv {
    name = "focaccia-artifact-environment";
    paths = commandPackages ++ stablePackages;
    pathsToLink = [
      "/bin"
      "/share/fonts"
    ];
  };
  directories = pkgs.runCommand "focaccia-artifact-directories" { } ''
    mkdir -p "$out/artifacts" "$out/tmp/matplotlib"
  '';
  # Keep common runtimes separate from changing evaluation scripts/configuration.
  dependencies = nix2container.buildLayer {
    deps = stablePackages ++ dependencyPackages;
  };
  image = nix2container.buildImage {
    name = "focaccia-artifact";
    inherit tag;
    layers = [ dependencies ];
    copyToRoot = [
      pkgs.dockerTools.fakeNss
      environment
      directories
    ];
    perms = [
      {
        path = directories;
        regex = "^${directories}/tmp(/matplotlib)?$";
        mode = "1777";
      }
    ];
    config = {
      Cmd = [ "/bin/bash" ];
      Env = [
        "HOME=/tmp"
        "TMPDIR=/tmp"
        "FONTCONFIG_FILE=${fontsConf}"
        "MPLCONFIGDIR=/tmp/matplotlib"
        "PATH=/bin"
        "PYTHONUNBUFFERED=1"
      ];
      WorkingDir = "/artifacts";
      Volumes = {
        "/artifacts" = { };
      };
      Labels = {
        "org.opencontainers.image.title" = "Focaccia artifact evaluation";
        "org.opencontainers.image.source" = "https://github.com/TUM-DSE/focaccia-eval";
        "org.opencontainers.image.revision" = self.rev or "dirty";
        "org.opencontainers.image.licenses" = "BSD-3-Clause";
        "io.focaccia.system" = system;
        "io.focaccia.focaccia-revision" = focaccia.rev or "dirty";
      };
    };
  };
  # Descriptor/transport checks need no daemon, registry, native tracing or RR.
  builderInterfaceCheck =
    assert image.imageName == "focaccia-artifact";
    assert image.imageTag == tag;
    pkgs.runCommand "nix2container-builder-interface"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        jq -e --arg arch '${pkgs.go.GOARCH}' \
          --arg directories '${directories}' \
          --arg environment '${environment}' \
          --slurpfile dependencies '${dependencies}/layers.json' '
          .version == 1 and .arch == $arch and
          (.layers | length == 2) and
          .layers[0] == $dependencies[0][0] and
          ([.layers[].paths[].path] as $paths |
            ($paths | length) == ($paths | unique | length)) and
          ([.layers[1].paths[] | select(.path == $environment) |
            .options.rewrite.repl] == [""]) and
          ([.layers[1].paths[] | select(.path == $directories) |
            .options.perms[] |
            .regex as $regex |
            select(.mode == "1777" and
              ($directories + "/tmp" | test($regex)) and
              ($directories + "/tmp/matplotlib" | test($regex)) and
              ($directories + "/artifacts" | test($regex) | not))] | length == 1) and
          all(.layers[]; .digest | test("^sha256:[0-9a-f]{64}$")) and
          all(.layers[]; has("layer-path") | not)
        ' ${image} > /dev/null
        test -d '${directories}/artifacts'
        test -d '${directories}/tmp/matplotlib'
        test -x ${image.copyToDockerDaemon}/bin/copy-to-docker-daemon
        test -x ${image.copyToRegistry}/bin/copy-to-registry
        touch "$out"
      '';
  loadApplication = pkgs.writeShellScriptBin "load-docker-artifact" ''
    exec ${image.copyToDockerDaemon}/bin/copy-to-docker-daemon "$@"
  '';
  transportCheck = pkgs.runCommand "docker-artifact-transport-interface"
    { nativeBuildInputs = [ pkgs.jq ]; }
    ''
      # nix2container emits a versioned descriptor, not a docker-load archive.
      jq -e '.version == 1 and .["image-config"].Cmd != null' ${image} >/dev/null
      test -x ${loadApplication}/bin/load-docker-artifact
      grep -F '${image.copyToDockerDaemon}/bin/copy-to-docker-daemon' \
        ${loadApplication}/bin/load-docker-artifact >/dev/null
      ! grep -F 'docker load < result' ${../README.md}
      grep -F 'nix run -L .#load-docker-artifact' ${../README.md} >/dev/null
      grep -F 'nix run -L .#load-docker-artifact' ${../evaluation/README.md} >/dev/null
      touch "$out"
    '';
  rootCommandPathCheck = pkgs.runCommand "docker-artifact-root-command-path"
    { nativeBuildInputs = [ pkgs.jq ]; }
    ''
      jq -e --arg environment '${environment}' '
        .["image-config"].Cmd == ["/bin/bash"] and
        (.["image-config"].Env | index("PATH=/bin")) != null and
        ([.layers[].paths[] | select(.path == $environment) |
          .options.rewrite.repl] == [""])
      ' ${image} >/dev/null
      touch "$out"
    '';
  interfaceCheck =
    pkgs.runCommand "docker-artifact-interface"
      {
        nativeBuildInputs = [
          pkgs.jq
        ];
      }
      ''
        jq -e \
          --arg shell '/bin/bash' \
          --arg fontconfig 'FONTCONFIG_FILE=${fontsConf}' \
          --arg path 'PATH=/bin' \
          --arg system '${system}' \
          '.["image-config"] | .Entrypoint == null and
           .Cmd == [$shell] and
           .WorkingDir == "/artifacts" and
           .Volumes["/artifacts"] == {} and
           .Labels["io.focaccia.system"] == $system and
           (.Env | index("HOME=/tmp")) != null and
           (.Env | index("TMPDIR=/tmp")) != null and
           (.Env | index($fontconfig)) != null and
           (.Env | index("MPLCONFIGDIR=/tmp/matplotlib")) != null and
           (.Env | index($path)) != null and
           (.Env | index("PYTHONUNBUFFERED=1")) != null' \
          ${image} >/dev/null

        export PATH=${environment}/bin
        export HOME="$TMPDIR"
        export FONTCONFIG_FILE=${fontsConf}
        export MPLCONFIGDIR="$TMPDIR/matplotlib"
        mkdir -p "$MPLCONFIGDIR"
        test -d ${environment}/share/fonts
        fc-match --format '%{family}\n' 'Linux Libertine O' \
          | grep -F 'Linux Libertine O'
        for command in ${lib.escapeShellArgs commandNames}; do
          test -x "${environment}/bin/$command"
          "$command" --help >"$command-help.txt"
        done
        bash -c 'test "$0" = bash'
        touch "$out"
      '';
in
{
  inherit
    environment
    image
    interfaceCheck
    builderInterfaceCheck
    loadApplication
    transportCheck
    rootCommandPathCheck
    tag
    ;
}
