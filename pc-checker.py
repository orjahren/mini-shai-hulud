import os

from script import find_vulnerabilities_in_repo, parse_vulnerabilities


root_scan_path = os.path.expanduser("~/")
SUPPORTED_LOCK_FILES = ["package-lock.json", "yarn.lock"]
INGORED_PATHS = ["node_modules", "vendor", "dist", "build", "target"]

DEBUG = False

if __name__ == "__main__":
    print("Scanning for vulnerabilities in repositories...")
    lockfiles = []

    print(f"Walking through {root_scan_path} to find lock files...")

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
            if file in SUPPORTED_LOCK_FILES:
                lockfile_path = os.path.join(root, file)
                if DEBUG:
                    print(f"Found {file} at: {lockfile_path}")
                lockfiles.append(lockfile_path)

    vulnerabilities_data = parse_vulnerabilities("data.md")

    # Accumulate results and print after all scans
    all_results = {}  # repo_dir -> list[RepoPackage]
    processed_repos = set()

    for lockfile in lockfiles:
        repo_dir = os.path.dirname(lockfile)

        # Avoid scanning same repo multiple times if multiple lockfiles exist
        if repo_dir in processed_repos:
            continue
        processed_repos.add(repo_dir)

        if DEBUG:
            print(
                f"Processing repository at {repo_dir} with lock file {lockfile}...")

        report = find_vulnerabilities_in_repo(repo_dir, vulnerabilities_data)
        all_results[repo_dir] = report.vulnerabilities

    # Final output after all scans complete
    print("\n=== Scan complete ===")
    print(f"Total lockfiles checked: {len(lockfiles)}")
    repos_with_vulns = {k: v for k, v in all_results.items() if v}

    if repos_with_vulns:
        print(
            f"Vulnerabilities found in {len(repos_with_vulns)} repository(ies):")
        for repo_dir, vulns in repos_with_vulns.items():
            print(f"\n{repo_dir}:")
            for vuln in vulns:
                print(f"- {vuln.package_name} {vuln.version}")
    else:
        print("No vulnerabilities found.")
