import os

from script import find_vulnerabilities_in_repo, parse_vulnerabilities


root_scan_path = os.path.expanduser("~/")
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

    # Accumulate results and print after all scans
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
