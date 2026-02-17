# test_sandbox.py
from spectr.sandbox import execute_in_sandbox

bad_code = "import os; os.listdir('/')"
success, result = execute_in_sandbox(bad_code)
print(f"Blocked as expected: {not success} | Error: {result.get('error')}")
