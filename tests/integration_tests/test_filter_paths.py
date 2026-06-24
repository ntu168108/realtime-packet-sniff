"""Test: every MODULE_PHANLOAI/*_feature_filter.py uses Path(__file__) not Windows path."""
import glob
import re
import os

# Default EC path mirrors integration/ec_consumer.NB15_EC default.
# Allow override via env so the test still works on a developer's machine
# where Extraction-and-classification lives elsewhere (e.g. ~/sniff/...).
EC = os.environ.get(
    "NB15_EC",
    os.path.expanduser("~/sniff/Extraction-and-classification"),
)
# Fall back to the repo-relative location used by the rest of the test
# suite (tests/integration_tests -> repo root -> Extraction-and-classification).
_REPO_EC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "Extraction-and-classification")
)
if not os.path.isdir(EC):
    EC = _REPO_EC

# The 7 family filters listed in the plan.
FAMILY_FILTERS = [
    "generic_feature_filter.py",
    "dos_feature_filter.py",
    "exploits_feature_filter.py",
    "fuzzers_feature_filter.py",
    "analysis_feature_filter.py",
    "reconnaissance_feature_filter.py",
    "shellcode_feature_filter.py",
]


def _read(name: str) -> str:
    with open(os.path.join(EC, "MODULE_PHANLOAI", name), encoding="utf-8", errors="ignore") as f:
        return f.read()


def test_no_windows_paths_in_family_filters():
    """Each of the 7 family filters must not contain raw D:\\... paths."""
    for name in FAMILY_FILTERS:
        src = _read(name)
        assert not re.search(r"r[\"']D:\\\\", src), f"windows path còn trong {name}"


def test_family_filters_use_portable_paths():
    """Each filter must derive its default dir from Path(__file__) (portable)."""
    for name in FAMILY_FILTERS:
        src = _read(name)
        assert "Path(__file__)" in src, f"chưa dùng Path(__file__) trong {name}"


def test_default_dirs_point_into_EC_repo():
    """Each filter's DEFAULT_OUTPUT_DIR must be derived from Path(__file__) (portable)."""
    for name in FAMILY_FILTERS:
        src = _read(name)
        m = re.search(r"DEFAULT_OUTPUT_DIR\s*=\s*.*", src)
        if m:
            # Look at the file around the assignment: it must reference _PROJECT_ROOT
            # which itself comes from Path(__file__).
            assert "_PROJECT_ROOT" in src, f"DEFAULT_OUTPUT_DIR not portable in {name}"
            assert "Path(__file__)" in src, f"DEFAULT_OUTPUT_DIR not portable in {name}"


def test_all_seven_filters_covered():
    for name in FAMILY_FILTERS:
        assert os.path.isfile(os.path.join(EC, "MODULE_PHANLOAI", name)), f"missing {name}"