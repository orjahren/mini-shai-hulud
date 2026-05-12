import json
import os
from dataclasses import dataclass, field
from typing import Dict, List

DEBUG = False


@dataclass
class Vulnerability:
    package_name: str
    versions: List[str]


@dataclass
class RepoVulnerabilityReport:
    repo_path: str
    vulnerabilities: List['RepoPackage']


@dataclass
class RepoPackage:
    repo_path: str
    package_name: str
    version: str
    source: str = "lockfile"
    dependencies: List['RepoDependency'] = field(default_factory=list)


@dataclass
class RepoDependency:
    repo_path: str
    dependency_name: str
    version_range: str
    parent_package: RepoPackage


def parse_vulnerabilities(file_path: str, debug=False) -> Dict[str, Vulnerability]:

    def line_to_vulnerability(line: str) -> Vulnerability:

        if debug:
            print(f"Parsing line: {line}")
        name = line[1:].split("|")[0].strip()
        # Fjerner fnutter om det finnes
        if name.startswith('`') and name.endswith('`'):
            name = name[1:-1]
        if debug:
            print(f"Extracted package name: {name}")

        versions = line[1:].split("|")[1].strip().split(",")
        versions = [version.strip() for version in versions]
        if debug:
            print(f"Extracted versions: {versions}")
        return Vulnerability(package_name=name, versions=versions)

    vulnerabilities = {}
    with open(file_path, 'r', encoding='utf-8') as file:
        raw = file.readlines()

        for line in raw:
            if line.startswith("|") and not line.startswith("| ---"):

                stripped = line.strip()
                if debug:
                    print(stripped)
                vulnerability = line_to_vulnerability(stripped)
                vulnerabilities[vulnerability.package_name] = vulnerability

    # Første item er headers, de vil vi ikke ha med
    del vulnerabilities["Package"]  # TODO: Denne burde aldri legges inn lul

    return vulnerabilities


# TODO: Burde bare prosesssere én lockfile av gangen
def get_packages_in_repo(repo_path: str) -> List[RepoPackage]:
    def find_package_lock_files(repo_path: str, file_names=["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]) -> List[str]:
        all_files = os.listdir(repo_path)  # TODO: Burde også sjekke submapper?
        found_files = []
        for file in all_files:
            if DEBUG:
                print(f"Checking file: {file} in {repo_path}")
            if file in file_names:  # TODO: This is fine mtp abs/rel paths?
                found_files.append(file)
                if DEBUG:
                    print(f"Found lock file: {file} in {repo_path}")
        return found_files

    def get_all_packages_in_repo_npm(package_lock_files: List[str]) -> List[RepoPackage]:
        packages: List[RepoPackage] = []

        with open(os.path.join(repo_path, package_lock_files[0]), 'r', encoding='utf-8') as file:
            parsed_lock_file = json.load(file)

        root_name = parsed_lock_file.get("name", "<root package>")

        for package_path, package_info in parsed_lock_file.get("packages", {}).items():
            package_name = package_info.get("name")
            if not package_name:
                if package_path == "":
                    package_name = root_name
                else:
                    package_name = package_path.split("node_modules/")[-1]

            package = RepoPackage(
                repo_path=repo_path,
                package_name=package_name,
                version=package_info.get("version", "")
            )
            packages.append(package)

            for dependency_name, dependency_version in package_info.get("dependencies", {}).items():
                package.dependencies.append(
                    RepoDependency(
                        repo_path=repo_path,
                        dependency_name=dependency_name,
                        version_range=dependency_version,
                        parent_package=package
                    )
                )

        return packages

    def get_all_packages_in_repo_yarn(package_lock_files: List[str]) -> List[RepoPackage]:
        packages: List[RepoPackage] = []
        yarn_lock_path = os.path.join(repo_path, package_lock_files[0])

        with open(yarn_lock_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        def selector_to_name(selector: str) -> str:
            s = selector.strip().strip('"').strip("'")
            return s.rsplit("@", 1)[0] if "@" in s else s

        def is_header_line(raw: str) -> bool:
            stripped = raw.strip()
            if not stripped:
                return False
            if raw[:1].isspace():
                return False
            if stripped.startswith("#"):
                return False
            if stripped == "__metadata:":
                return False
            return stripped.endswith(":")

        def parse_entry(entry_lines: List[str]) -> None:
            if not entry_lines:
                return

            header = entry_lines[0].strip()
            selectors = [s.strip() for s in header[:-1].split(",")]
            version = ""
            dependencies: Dict[str, str] = {}

            in_dependencies = False
            for raw in entry_lines[1:]:
                stripped = raw.strip()

                if stripped.startswith("version "):
                    version = stripped.split("version ", 1)[
                        1].strip().strip('"').strip("'")
                    in_dependencies = False
                elif stripped in ("dependencies:", "optionalDependencies:"):
                    in_dependencies = True
                elif in_dependencies and raw[:1].isspace():
                    parts = stripped.split(" ", 1)
                    if len(parts) == 2:
                        dep_name = parts[0].strip('"').strip("'")
                        dep_range = parts[1].strip().strip('"').strip("'")
                        dependencies[dep_name] = dep_range
                else:
                    in_dependencies = False

            for selector in selectors:
                pkg_name = selector_to_name(selector)
                package = RepoPackage(
                    repo_path=repo_path,
                    package_name=pkg_name,
                    version=version
                )
                for dep_name, dep_range in dependencies.items():
                    package.dependencies.append(
                        RepoDependency(
                            repo_path=repo_path,
                            dependency_name=dep_name,
                            version_range=dep_range,
                            parent_package=package
                        )
                    )
                packages.append(package)

        current_entry: List[str] = []
        for raw in lines:
            if is_header_line(raw):
                parse_entry(current_entry)
                current_entry = [raw]
            else:
                if current_entry:
                    current_entry.append(raw)
        parse_entry(current_entry)

        # Ensure dependencies are represented as package nodes too (test expects this)
        existing_names = {p.package_name for p in packages}
        for pkg in list(packages):
            for dep in pkg.dependencies:
                if dep.dependency_name not in existing_names:
                    packages.append(
                        RepoPackage(
                            repo_path=repo_path,
                            package_name=dep.dependency_name,
                            version=dep.version_range
                        )
                    )
                    existing_names.add(dep.dependency_name)

        return packages

    lock_files = find_package_lock_files(repo_path)
    if DEBUG:
        print(f"Lock files found in {repo_path}: {lock_files}")
    match lock_files:
        case []:
            if DEBUG:
                print(
                    f"No lock files found in {repo_path}. Skipping vulnerability check.")
            return []
        case ["package-lock.json"]:
            if DEBUG:
                print("NPM lock file found.")
            return get_all_packages_in_repo_npm(lock_files)
        case ["yarn.lock"]:
            if DEBUG:
                print("Yarn lock file found.")
            return get_all_packages_in_repo_yarn(lock_files)
        case _:
            if DEBUG:
                print(
                    f"Unsupported lock file(s) found in {repo_path}: {lock_files}.")
            return []


def _to_semver_parts(value: str) -> list[int] | None:
    v = value.strip().strip('"').strip("'")
    # Allow ranges on "version" input side too (e.g. "^4.17.21")
    if v.startswith("^") or v.startswith("~"):
        v = v[1:]

    parts = v.split(".")
    if not all(p.isdigit() for p in parts):
        return None

    nums = [int(p) for p in parts]
    while len(nums) < 3:
        nums.append(0)
    return nums[:3]


def satisfies_caret_range(version_str: str, caret_range: str) -> bool:
    version_parts = _to_semver_parts(version_str)
    if version_parts is None:
        return False

    if not caret_range.startswith("^"):
        exact = _to_semver_parts(caret_range)
        return exact is not None and version_parts == exact

    base_parts = _to_semver_parts(caret_range[1:])
    if base_parts is None:
        return False

    if base_parts[0] > 0:
        return version_parts[0] == base_parts[0] and version_parts >= base_parts
    if base_parts[1] > 0:
        return version_parts[0] == 0 and version_parts[1] == base_parts[1] and version_parts >= base_parts
    return version_parts[0] == 0 and version_parts[1] == 0 and version_parts[2] >= base_parts[2]


def find_vulnerabilities_in_repo(repo_path: str, vulnerabilities: Dict[str, Vulnerability]) -> RepoVulnerabilityReport:
    packages_in_repo = get_packages_in_repo(repo_path)
    affected_packages: List[RepoPackage] = []
    seen = set()

    def has_direct_package(dep_name: str) -> bool:
        return any(p.package_name == dep_name for p in packages_in_repo)

    for package in packages_in_repo:
        direct_hit = package.package_name in vulnerabilities

        # Only use indirect hit if dependency is not already represented directly.
        indirect_hit = any(
            dep.dependency_name in vulnerabilities
            for dep in package.dependencies
        )

        if direct_hit or indirect_hit:
            key = (package.package_name, package.version)
            if key not in seen:
                seen.add(key)
                affected_packages.append(package)

    return RepoVulnerabilityReport(repo_path=repo_path, vulnerabilities=affected_packages)


if __name__ == "__main__":
    REPO_PATHS = [
        "../../nettskjema/",
        "../../nettskjema-frontend/",
        "../../go-svaring/",
        "../../nettskjema-npm/",
    ]
    all_vulnerabilities = parse_vulnerabilities("data.md")
    # print(all_vulnerabilities)
    all_repo_vulnerabilities = []
    if DEBUG:
        print(
            f"Finished parsing {len(all_vulnerabilities)} vulnerabilities.")
    for repo_path in REPO_PATHS:
        report = find_vulnerabilities_in_repo(
            repo_path, all_vulnerabilities)
        if DEBUG:
            print(f"Vulnerabilities in {repo_path}: {report}")
        all_repo_vulnerabilities.append(report)
        if DEBUG:
            print(f"Finished checking {repo_path}.")
    for report in all_repo_vulnerabilities:
        print(
            f"Repository: {report.repo_path}, Vulnerabilities: {len(report.vulnerabilities)}")
