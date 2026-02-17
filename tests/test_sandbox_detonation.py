from spectr.sandbox import execute_in_sandbox


def test_detonation():
    print("--- Testing Sandbox Boundaries ---")

    # Test Case 1: The "Good" Code
    good_code = "x = 10; y = 20; result = x + y"
    success, meta = execute_in_sandbox(good_code)
    print(
        f"Safe Code: {'PASSED' if success else 'FAILED'} (Result: {meta.get('result', 'None')})"
    )

    # Test Case 2: The "Malicious" Code (Import Violation)
    evil_code = "import os; os.system('whoami')"
    success, meta = execute_in_sandbox(evil_code)
    print(
        f"Evil Code: {'BLOCKED' if not success else 'ESCAPED!'} (Error: {meta.get('error')})"
    )


if __name__ == "__main__":
    test_detonation()
