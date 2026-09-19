from pathlib import Path

DEFAULT_CASE_ROOT = Path("./cases")

# Source checkouts retain the editable data directory. Installed wheels carry
# the same resources inside the package and do not need the source checkout.
REPO_ROOT = Path(__file__).resolve().parents[2]
_PACKAGE_DIR = Path(__file__).resolve().parent
_BUNDLED_DATA_DIR = (
    REPO_ROOT / "data"
    if (_PACKAGE_DIR == REPO_ROOT / "src" / "seclogx"
        and (REPO_ROOT / "data").is_dir())
    else _PACKAGE_DIR / "_bundled_data"
)
BUNDLED_SIGMA_RULES_DIR = _BUNDLED_DATA_DIR / "sigma_rules"
BUNDLED_ATTACK_DATA = _BUNDLED_DATA_DIR / "attack" / "techniques.json"
BUNDLED_SCHEDULED_TASK_BASELINE = _BUNDLED_DATA_DIR / "scheduled_tasks" / "known_microsoft_tasks.json"
