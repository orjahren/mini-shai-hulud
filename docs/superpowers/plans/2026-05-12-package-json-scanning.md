# package.json Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend mini-shai-hulud to scan `package.json` files for compromised package names (name-only, no version check), in addition to the existing lock file scanning.

**Architecture:** Add a `source` field to `RepoPackage` to tag each result as `"lockfile"` or `"package.json"`. A new `get_packages_from_package_json()` function reads all five dependency fields and returns tagged packages with no version. `get_packages_in_repo()` merges both sources into one list; `pc-checker.py` splits results by source at output time.

**Tech Stack:** Python 3.10+, stdlib only (`json`, `os`, `dataclasses`), `unittest`

---

## File Map

| File | Change |
|---|---|
| `script.py` | Add `source` field to `RepoPackage`; add `get_packages_from_package_json()`; update `get_packages_in_repo()` |
| `pc-checker.py` | Discover repos via lock files OR `package.json`; split output into two sections |
| `test_script.py` | Add 4 new test cases for package.json scanning |

---

### Task 1: Add `source` field to `RepoPackage`

**Files:**
- Modify: `script.py` (the `RepoPackage` dataclass, around line 22)

- [ ] **Step 1: Add `source` field with default `"lockfile"`**

In `script.py`, update `RepoPackage`:

```python
@dataclass
class RepoPackage:
    repo_path: str
    package_name: str
    version: str
    source: str = "lockfile"
    dependencies: List['RepoDependency'] = field(default_factory=list)
```

The field must come before `dependencies` (which has a `field(default_factory=...)` default) and after the non-default fields, so Python's dataclass ordering is satisfied.

- [ ] **Step 2: Run existing tests to confirm nothing broke**

```bash
python -m pytest test_script.py -v
```

Expected: all 4 existing tests pass. The new field has a default so no callers need updating.

- [ ] **Step 3: Commit**

```bash
git add script.py
git commit --no-gpg-sign -m "feat: add source field to RepoPackage"
```

---

### Task 2: Implement and test `get_packages_from_package_json`

**Files:**
- Modify: `script.py` (add new function after `get_packages_in_repo`)
- Modify: `test_script.py` (add `test_package_json_parsing`)

- [ ] **Step 1: Write the failing test**

Add this test to the `TestPackageParsingAndVulnerabilities` class in `test_script.py`:

```python
def test_package_json_parsing(self):
    """
    Test that get_packages_in_repo includes packages from all dependency fields
    in package.json, tagged with source="package.json".
    """
    package_json_data = {
        "name": "test-project",
        "dependencies": {"lodash": "^4.17.21"},
        "devDependencies": {"jest": "^29.0.0"},
        "peerDependencies": {"react": ">=16"},
        "optionalDependencies": {"fsevents": "^2.3.0"},
        "bundledDependencies": ["some-bundled-pkg"]
    }
    pj_path = os.path.join(self.TEST_DIR, "package.json")
    with open(pj_path, "w", encoding="utf-8") as f:
        json.dump(package_json_data, f)

    packages = get_packages_in_repo(self.TEST_DIR)
    self.assertEqual(len(packages), 5)

    names = {p.package_name for p in packages}
    self.assertIn("lodash", names)
    self.assertIn("jest", names)
    self.assertIn("react", names)
    self.assertIn("fsevents", names)
    self.assertIn("some-bundled-pkg", names)

    for p in packages:
        self.assertEqual(p.source, "package.json")
        self.assertEqual(p.version, "")
```

- [ ] **Step 2: Run to confirm it fails**

```bash
python -m pytest test_script.py::TestPackageParsingAndVulnerabilities::test_package_json_parsing -v
```

Expected: FAIL — `get_packages_in_repo` currently returns `[]` for a repo with no lock file.

- [ ] **Step 3: Implement `get_packages_from_package_json` in `script.py`**

Add this function inside `get_packages_in_repo` is not correct — add it as a **module-level function** in `script.py`, just before `get_packages_in_repo`:

```python
def get_packages_from_package_json(repo_path: str) -> List[RepoPackage]:
    package_json_path = os.path.join(repo_path, "package.json")
    try:
        with open(package_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

    packages: List[RepoPackage] = []
    seen_names: set = set()
    dep_fields = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
        "bundleDependencies",  # alternate spelling npm accepts
    ]

    for field_name in dep_fields:
        field_data = data.get(field_name)
        if field_data is None:
            continue
        if isinstance(field_data, list):
            # bundledDependencies can be a list of package name strings
            for package_name in field_data:
                if isinstance(package_name, str) and package_name not in seen_names:
                    seen_names.add(package_name)
                    packages.append(RepoPackage(
                        repo_path=repo_path,
                        package_name=package_name,
                        version="",
                        source="package.json"
                    ))
        elif isinstance(field_data, dict):
            for package_name in field_data:
                if package_name not in seen_names:
                    seen_names.add(package_name)
                    packages.append(RepoPackage(
                        repo_path=repo_path,
                        package_name=package_name,
                        version="",
                        source="package.json"
                    ))

    return packages
```

- [ ] **Step 4: Update `get_packages_in_repo` to always call `get_packages_from_package_json`**

The current function ends with a `match` statement that returns early. Restructure so package.json packages are always appended:

```python
def get_packages_in_repo(repo_path: str) -> List[RepoPackage]:
    def find_package_lock_files(repo_path: str, file_names=["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]) -> List[str]:
        all_files = os.listdir(repo_path)
        found_files = []
        for file in all_files:
            if DEBUG:
                print(f"Checking file: {file} in {repo_path}")
            if file in file_names:
                found_files.append(file)
                if DEBUG:
                    print(f"Found lock file: {file} in {repo_path}")
        return found_files

    # (keep get_all_packages_in_repo_npm and get_all_packages_in_repo_yarn unchanged)

    lock_files = find_package_lock_files(repo_path)
    if DEBUG:
        print(f"Lock files found in {repo_path}: {lock_files}")

    packages: List[RepoPackage] = []

    match lock_files:
        case []:
            if DEBUG:
                print(f"No lock files found in {repo_path}.")
        case ["package-lock.json"]:
            if DEBUG:
                print("NPM lock file found.")
            packages = get_all_packages_in_repo_npm(lock_files)
        case ["yarn.lock"]:
            if DEBUG:
                print("Yarn lock file found.")
            packages = get_all_packages_in_repo_yarn(lock_files)
        case _:
            if DEBUG:
                print(f"Unsupported lock file(s) found in {repo_path}: {lock_files}.")

    packages.extend(get_packages_from_package_json(repo_path))
    return packages
```

- [ ] **Step 5: Run the new test**

```bash
python -m pytest test_script.py::TestPackageParsingAndVulnerabilities::test_package_json_parsing -v
```

Expected: PASS

- [ ] **Step 6: Run full test suite to confirm no regressions**

```bash
python -m pytest test_script.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 7: Commit**

```bash
git add script.py test_script.py
git commit --no-gpg-sign -m "feat: add package.json scanning to get_packages_in_repo"
```

---

### Task 3: Add vulnerability detection tests for `package.json`

**Files:**
- Modify: `test_script.py` (add 3 more test cases)

- [ ] **Step 1: Write the three new tests**

Add all three to the `TestPackageParsingAndVulnerabilities` class in `test_script.py`:

```python
def test_package_json_vulnerability_detection(self):
    """
    Test that a vulnerable package listed in package.json is flagged by name.
    """
    package_json_data = {
        "dependencies": {"lodash": "^4.17.21"}
    }
    pj_path = os.path.join(self.TEST_DIR, "package.json")
    with open(pj_path, "w", encoding="utf-8") as f:
        json.dump(package_json_data, f)

    report = find_vulnerabilities_in_repo(self.TEST_DIR, vulnerabilities_data)

    self.assertEqual(len(report.vulnerabilities), 1)
    self.assertEqual(report.vulnerabilities[0].package_name, "lodash")
    self.assertEqual(report.vulnerabilities[0].source, "package.json")
    self.assertEqual(report.vulnerabilities[0].version, "")

def test_package_json_no_false_positive(self):
    """
    Test that non-vulnerable packages in package.json produce an empty report.
    """
    package_json_data = {
        "dependencies": {"axios": "^1.6.0"},
        "devDependencies": {"typescript": "^5.0.0"}
    }
    pj_path = os.path.join(self.TEST_DIR, "package.json")
    with open(pj_path, "w", encoding="utf-8") as f:
        json.dump(package_json_data, f)

    report = find_vulnerabilities_in_repo(self.TEST_DIR, vulnerabilities_data)

    self.assertEqual(len(report.vulnerabilities), 0)

def test_repo_with_both_lockfile_and_package_json(self):
    """
    Test that a repo with both a lock file and a package.json reports
    vulnerabilities from both sources independently.
    """
    # Lock file: lodash 4.17.21 (vulnerable)
    npm_lock_path = os.path.join(self.TEST_DIR, "package-lock.json")
    with open(npm_lock_path, "w", encoding="utf-8") as f:
        json.dump(npm_lock_data, f, indent=2)

    # package.json: lodash (vulnerable by name)
    package_json_data = {"dependencies": {"lodash": "^4.17.21"}}
    pj_path = os.path.join(self.TEST_DIR, "package.json")
    with open(pj_path, "w", encoding="utf-8") as f:
        json.dump(package_json_data, f)

    packages = get_packages_in_repo(self.TEST_DIR)
    lockfile_pkgs = [p for p in packages if p.source == "lockfile"]
    pj_pkgs = [p for p in packages if p.source == "package.json"]
    self.assertGreater(len(lockfile_pkgs), 0)
    self.assertGreater(len(pj_pkgs), 0)

    report = find_vulnerabilities_in_repo(self.TEST_DIR, vulnerabilities_data)
    sources = {v.source for v in report.vulnerabilities}
    self.assertIn("lockfile", sources)
    self.assertIn("package.json", sources)
```

- [ ] **Step 2: Run the new tests**

```bash
python -m pytest test_script.py::TestPackageParsingAndVulnerabilities::test_package_json_vulnerability_detection test_script.py::TestPackageParsingAndVulnerabilities::test_package_json_no_false_positive test_script.py::TestPackageParsingAndVulnerabilities::test_repo_with_both_lockfile_and_package_json -v
```

Expected: all 3 PASS (no code changes needed — `find_vulnerabilities_in_repo` already does name-based matching).

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest test_script.py -v
```

Expected: all 8 tests pass.

- [ ] **Step 4: Commit**

```bash
git add test_script.py
git commit --no-gpg-sign -m "test: add package.json vulnerability detection tests"
```

---

### Task 4: Update `pc-checker.py` for discovery and split output

**Files:**
- Modify: `pc-checker.py`

- [ ] **Step 1: Update `pc-checker.py` with new discovery and output logic**

Replace the entire file content with the following (changes: discover repos via lock files OR `package.json`, rename `lockfiles` to `repo_dirs`, split final output into two sections):

```python
import os

from script import find_vulnerabilities_in_repo, parse_vulnerabilities


root_scan_path = os.path.expanduser("~/Documents")
DISCOVERED_FILES = ["package-lock.json", "yarn.lock", "package.json"]
INGORED_PATHS = ["node_modules", "vendor", "dist", "build", "target"]

DEBUG = False

if __name__ == "__main__":
    print("Scanning for vulnerabilities in repositories...")
    repo_dirs = set()

    print(f"Walking through {root_scan_path} to find repos...")

    for root, dirs, files in os.walk(root_scan_path):
        # Skip ignored paths and any folder containing 'onedrive' (case-insensitive)
        dirs[:] = [
            d for d in dirs
            if d.lower() not in [p.lower() for p in INGORED_PATHS]
            and "onedrive" not in d.lower()
        ]
        if DEBUG:
            print(f"Scanning {root}...")
        for file in files:
            if DEBUG:
                print(f"Checking {file} in {root}...")
            if file in DISCOVERED_FILES:
                if DEBUG:
                    print(f"Found {file} at: {root}")
                repo_dirs.add(root)

    vulnerabilities_data = parse_vulnerabilities("data.md")

    all_results = {}  # repo_dir -> list[RepoPackage]

    for repo_dir in repo_dirs:
        if DEBUG:
            print(f"Processing repository at {repo_dir}...")

        report = find_vulnerabilities_in_repo(repo_dir, vulnerabilities_data)
        all_results[repo_dir] = report.vulnerabilities

    # Split results by source
    lockfile_hits = {
        k: [v for v in vulns if v.source == "lockfile"]
        for k, vulns in all_results.items()
    }
    pj_hits = {
        k: [v for v in vulns if v.source == "package.json"]
        for k, vulns in all_results.items()
    }

    # --- Lock file findings ---
    print("\n=== Scan complete ===")
    print(f"Total repos scanned: {len(all_results)}")

    repos_with_lockfile_vulns = {k: v for k, v in lockfile_hits.items() if v}
    if repos_with_lockfile_vulns:
        print(
            f"Lock file vulnerabilities found in {len(repos_with_lockfile_vulns)} repository(ies):")
        for repo_dir, vulns in repos_with_lockfile_vulns.items():
            print(f"\n{repo_dir}:")
            for vuln in vulns:
                print(f"- {vuln.package_name} {vuln.version}")
    else:
        print("No lock file vulnerabilities found.")

    # --- package.json findings ---
    print("\n=== package.json matches ===")
    repos_with_pj_hits = {k: v for k, v in pj_hits.items() if v}
    if repos_with_pj_hits:
        print(
            f"Packages found by name (version unconfirmed) in {len(repos_with_pj_hits)} repo(s):")
        for repo_dir, vulns in repos_with_pj_hits.items():
            print(f"\n{repo_dir}:")
            for vuln in vulns:
                print(f"- {vuln.package_name}")
    else:
        print("No package.json matches found.")
```

- [ ] **Step 2: Run the full test suite one final time**

```bash
python -m pytest test_script.py -v
```

Expected: all 8 tests pass.

- [ ] **Step 3: Commit**

```bash
git add pc-checker.py
git commit --no-gpg-sign -m "feat: update pc-checker to discover and report package.json matches"
```
