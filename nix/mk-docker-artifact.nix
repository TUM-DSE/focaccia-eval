{
  pkgs,
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
  environment = pkgs.buildEnv {
    name = "focaccia-artifact-environment";
    paths = commandPackages ++ [
      pkgs.bashInteractive
      pkgs.coreutils
      pkgs.findutils
      pkgs.fontconfig
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
      pkgs.libertine
    ];
    pathsToLink = [
      "/bin"
      "/share/fonts"
    ];
  };
  image = pkgs.dockerTools.buildLayeredImage {
    name = "focaccia-artifact";
    inherit tag;
    contents = [
      pkgs.dockerTools.fakeNss
      environment
    ];
    extraCommands = ''
      mkdir -p artifacts tmp/matplotlib
      chmod 1777 tmp tmp/matplotlib
    '';
    config = {
      Cmd = [ "${environment}/bin/bash" ];
      Env = [
        "HOME=/tmp"
        "TMPDIR=/tmp"
        "FONTCONFIG_FILE=${fontsConf}"
        "MPLCONFIGDIR=/tmp/matplotlib"
        "PATH=${environment}/bin"
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
  interfaceCheck =
    pkgs.runCommand "docker-artifact-interface"
      {
        nativeBuildInputs = [
          pkgs.gnutar
          pkgs.jq
        ];
      }
      ''
        mkdir image
        tar -xf ${image} -C image
        config_file="$(jq -r '.[0].Config' image/manifest.json)"
        jq -e \
          --arg tag 'focaccia-artifact:${tag}' \
          '.[0].RepoTags == [$tag]' \
          image/manifest.json >/dev/null
        jq -e \
          --arg shell '${environment}/bin/bash' \
          --arg fontconfig 'FONTCONFIG_FILE=${fontsConf}' \
          --arg path 'PATH=${environment}/bin' \
          --arg system '${system}' \
          '.config.Entrypoint == null and
           .config.Cmd == [$shell] and
           .config.WorkingDir == "/artifacts" and
           .config.Volumes["/artifacts"] == {} and
           .config.Labels["io.focaccia.system"] == $system and
           (.config.Env | index("HOME=/tmp")) != null and
           (.config.Env | index("TMPDIR=/tmp")) != null and
           (.config.Env | index($fontconfig)) != null and
           (.config.Env | index("MPLCONFIGDIR=/tmp/matplotlib")) != null and
           (.config.Env | index($path)) != null' \
          "image/$config_file" >/dev/null

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
    tag
    ;
}
