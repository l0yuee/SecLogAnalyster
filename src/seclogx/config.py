from pathlib import Path

DEFAULT_CASE_ROOT = Path("./cases")

# Repo root, used to locate bundled data/ (sigma rules, ATT&CK lookup) when
# running from a source checkout / editable install.
REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLED_SIGMA_RULES_DIR = REPO_ROOT / "data" / "sigma_rules"
BUNDLED_ATTACK_DATA = REPO_ROOT / "data" / "attack" / "techniques.json"
BUNDLED_SCHEDULED_TASK_BASELINE = REPO_ROOT / "data" / "scheduled_tasks" / "known_microsoft_tasks.json"
