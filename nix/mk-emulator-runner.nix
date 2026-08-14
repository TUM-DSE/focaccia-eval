{ pkgs, system }:

name: stages:

let
  lib = pkgs.lib;
  stageNames = lib.concatMapStringsSep ", " (stage: stage.label) stages;
  stageCommands = lib.concatMapStringsSep "\n" (stage: ''
    run_stage \
      ${lib.escapeShellArg stage.label} \
      ${lib.escapeShellArg stage.program}
  '') stages;
in
pkgs.writeShellScriptBin name ''
  set -u

  usage() {
    cat <<'EOF'
  Usage: evaluate-emulator --input RUN [--iterations N]

  Run every emulator-side evaluation applicable to this physical host.
  The same command is used on x86-64 and AArch64; Nix selects the
  host-specific stages automatically.

  Options:
    --input RUN       Shared evaluator run root (required)
    --iterations N    Measurement iterations (default: 1)
    -h, --help        Show this help

  Stages on ${system}: ${stageNames}
  EOF
  }

  fail() {
    printf 'evaluate-emulator: %s\n' "$1" >&2
    exit 2
  }

  input=
  input_set=0
  iterations=1
  iterations_set=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --input)
        [ "$#" -ge 2 ] || fail '--input requires a value'
        [ "$input_set" -eq 0 ] || fail '--input may be specified only once'
        input="$2"
        input_set=1
        shift 2
        ;;
      --input=*)
        [ "$input_set" -eq 0 ] || fail '--input may be specified only once'
        input="''${1#--input=}"
        input_set=1
        shift
        ;;
      --iterations)
        [ "$#" -ge 2 ] || fail '--iterations requires a value'
        [ "$iterations_set" -eq 0 ] || fail '--iterations may be specified only once'
        iterations="$2"
        iterations_set=1
        shift 2
        ;;
      --iterations=*)
        [ "$iterations_set" -eq 0 ] || fail '--iterations may be specified only once'
        iterations="''${1#--iterations=}"
        iterations_set=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unsupported argument: $1"
        ;;
    esac
  done

  [ "$input_set" -eq 1 ] || fail '--input is required'
  [ -n "$input" ] || fail '--input must not be empty'
  [ -n "$iterations" ] || fail '--iterations must be a positive integer'
  case "$iterations" in
    *[!0-9]*|0) fail '--iterations must be a positive integer' ;;
  esac

  status=0
  run_stage() {
    local label="$1"
    local program="$2"
    local stage_status
    printf '[${system}] emulator stage: %s\n' "$label"
    if "$program" \
      --input "$input" \
      --iterations "$iterations"
    then
      printf '[${system}] emulator stage passed: %s\n' "$label"
    else
      stage_status="$?"
      case "$stage_status" in
        130|143)
          printf \
            '[${system}] emulator evaluation interrupted (%s): %s\n' \
            "$stage_status" "$label" >&2
          exit "$stage_status"
          ;;
      esac
      printf \
        '[${system}] emulator stage failed (%s): %s\n' \
        "$stage_status" "$label" >&2
      status=1
    fi
  }

  ${stageCommands}
  exit "$status"
''
