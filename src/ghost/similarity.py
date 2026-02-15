import difflib
from typing import List, Optional
POPULAR_PACKAGES = ["requests", "pandas", "numpy", "boto3", "urllib3", "cryptography"]

def find_similar_package(target: str, threshold: float = 0.8)-> Optional[str]:
    matches = difflib.get_close_matches(target, POPULAR_PACKAGES, n=1, cutoff=threshold)
    return matches[0] if matches else None

def check_for_typosquatting(package_name: str) -> bool:
    if package_name in POPULAR_PACKAGES:
        return False
    return find_similar_package(package_name, threshold=0.85) is not None
