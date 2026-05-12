# Design: package.json Scanning

**Date:** 2026-05-12  
**Status:** Approved

## Overview

Extend mini-shai-hulud to scan `package.json` files in addition to lock files. Lock file scanning gives exact resolved versions; `package.json` scanning gives name-only matches (loose) since version ranges cannot be resolved without installing dependencies.

## Decisions

| Question | Decision |
|---|---|
| Version matching for package.json | Loose — flag if package name appears, regardless of version |
| Dependency fields to scan | All: `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundledDependencies` |
| Repos with both lock file and package.json | Report both separately — no deduplication |
| Output format | Two sections: lock file findings first, then a distinct `=== package.json matches ===` block |

## Architecture

### `RepoPackage` — new `source` field

Add a `source: str` field (default `"lockfile"`) to `RepoPackage`. This tags each package with where it came from so the output layer can split them.

### `script.py` — new `get_packages_from_package_json(repo_path)`

- Reads `package.json` from `repo_path`
- Extracts package names from all five dependency fields
- Returns `List[RepoPackage]` with `version=""` and `source="package.json"`
- If file is missing or malformed JSON: returns `[]` silently
- If no dependency fields present: returns `[]`

### `script.py` — `get_packages_in_repo()` updated

- Calls both the existing lock file parsers and `get_packages_from_package_json()`
- Combines results into one list
- Returns the unified list — callers are unchanged

### `script.py` — `find_vulnerabilities_in_repo()` updated

- For packages with `source="lockfile"`: existing exact version match logic (unchanged)
- For packages with `source="package.json"`: name-only match — if the package name is in the vulnerability dict, it is flagged (version is not checked)

### `pc-checker.py` — output section updated

After the existing lock file summary block, add a second block:

```
=== package.json matches ===
Packages found by name (version unconfirmed) in N repo(s):

<repo_dir>:
- <package_name>
```

If no `package.json` hits, print `No package.json matches found.`

## Error Handling

- Malformed `package.json`: silently skip, no crash
- `package.json` with no dependency fields: return empty list
- Repos with both sources: handled naturally — unified list, split at output

## Testing

New test cases in `test_script.py`:

- `test_package_json_parsing` — all five dependency fields parsed; packages have `source="package.json"` and empty version
- `test_package_json_vulnerability_detection` — vulnerable package name in `package.json` appears in `report.vulnerabilities`
- `test_package_json_no_false_positive` — non-vulnerable packages in `package.json` produce empty report
- `test_repo_with_both_lockfile_and_package_json` — both sources present; both appear in results independently

Existing `test_npm_*` and `test_yarn_*` tests remain unchanged. The `source` field defaults to `"lockfile"` so existing assertions are unaffected.
