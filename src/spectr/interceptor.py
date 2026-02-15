import textwrap


def generate_alias():
    """
    Outputs clean shell configuration to intercept package installs.
    """
    hook = """
        pip() {
            if [[ "$1" == "install" && -n "$2" && "$2" != -* ]]; then
               for pkg in "${@:2}"; do
                    # Skip flags like --upgrade or -r
                    if [[ "$pkg" != -* ]]; then
                        ghost "$pkg" || return 1
                    fi
                done
                command pip "$@"
            else
                command pip "$@"
            fi
        }

        uv() {
            if [[ "$1" == "pip" && "$2" == "install" && -n "$3" ]]; then
                ghost "$3"
                if [ $? -eq 0 ]; then
                    command uv "$@"
                else
                    echo "🛡️  Ghost blocked the installation of '$3'."
                    return 1
                fi
            else
                command uv "$@"
            fi
        }
    """
    # .strip() removes leading/trailing newlines that cause 'unexpected token' errors
    print(textwrap.dedent(hook).strip())


def remove_alias():
    """Outputs the shell commands to remove Spectr protection."""
    unhook = """
        unset -f pip
        unset -f uv
        echo "👻 Spectr protection disabled. Standard package managers restored."
    """
    print(textwrap.dedent(unhook).strip())
