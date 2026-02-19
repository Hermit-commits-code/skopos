#!/bin/bash

# Skopos v0.23.0 - The uv Command Wrapper
# This script intercepts 'add' and 'run' commands to perform a pre-install audit.

COMMAND=$1
shift # Move to the arguments

# Helper: run the skopos check using the installed CLI if available,
# otherwise fall back to `python -m skopos.checker` when importable.
run_skopos_check() {
    if command -v skopos >/dev/null 2>&1; then
        skopos check "$@"
        return $?
    fi

    # Fallback: try running as a module if skopos isn't on PATH
    if python -c "import importlib; importlib.import_module('skopos.checker')" >/dev/null 2>&1; then
        python -m skopos.checker check "$@"
        return $?
    fi

    # Neither CLI nor module available
    return 127
}

# If the wrapper is invoked with a skopos CLI subcommand (e.g. `check`),
# run the skopos CLI directly so users can call the script as a local shim.
case "$COMMAND" in
    check|audit|config|integrations|help|--help|-h)
        if command -v skopos >/dev/null 2>&1; then
            skopos "$COMMAND" "$@"
            exit $?
        fi

        if python -c "import importlib; importlib.import_module('skopos.checker')" >/dev/null 2>&1; then
            python -m skopos.checker "$COMMAND" "$@"
            exit $?
        fi

        # If we're in the repo root and `src/skopos` exists, add `src` to PYTHONPATH
        if [ -d "$(pwd)/src/skopos" ]; then
            PYTHONPATH=src python -m skopos.checker "$COMMAND" "$@"
            exit $?
        fi

        echo -e "\033[0;33m[Skopos] skopos not found; install or run from repo root.\033[0m" >&2
        exit 127
        ;;
    *)
        ;;
esac

if [[ "$COMMAND" == "add" || "$COMMAND" == "run" ]]; then
    # The last argument is usually the package name
    PACKAGE="${@: -1}"

    # Attempt to run the check. Exit code meanings:
    # 0 -> passed, non-zero -> failure, 127 -> skopos missing
    run_skopos_check "$PACKAGE"
    RC=$?
    if [[ $RC -eq 127 ]]; then
        echo -e "\033[0;33m[Skopos] skopos not found; skipping security check.\033[0m" >&2
    elif [[ $RC -ne 0 ]]; then
        echo -e "\033[0;31m[Skopos] Security Gate: Installation aborted due to high risk score.\033[0m" >&2
        return 1 2>/dev/null || exit 1
    fi
fi

# If we pass the check, or it's a non-install command, run the real uv
command uv "$COMMAND" "$@"