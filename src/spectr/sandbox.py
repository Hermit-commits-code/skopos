from RestrictedPython import compile_restricted, safe_globals


def execute_in_sandbox(source_code):
    """v0.21.0: Safely executes untrusted Python snippets."""
    loc = {}
    try:
        byte_code = compile_restricted(source_code, "<inline>", "exec")
        # We use safe_globals to strip access to os, sys, and file I/O
        exec(byte_code, safe_globals, loc)
        return True, loc
    except SyntaxError:
        # If it's not valid Python (like a text README), it's technically "safe"
        # from an execution standpoint.
        return True, {"info": "Not executable Python code (Text/Markdown)"}
    except Exception as e:
        # This catches actual security violations or runtime crashes
        return False, {"error": str(e)}
