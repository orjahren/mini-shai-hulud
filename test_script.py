import unittest
import os
import json
from script import get_packages_in_repo, find_vulnerabilities_in_repo, Vulnerability, RepoVulnerabilityReport

# Mock NPM package-lock.json data
npm_lock_data = {
    "name": "test-project",
    "version": "1.0.0",
    "packages": {
        "": {
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.15",
                "react": "^17.0.0"
            }
        },
        "node_modules/lodash": {
            "version": "4.17.21"
        },
        "node_modules/react": {
            "version": "17.0.2"
        }
    }
}

# Mock Yarn v1 yarn.lock data
yarn_lock_data = """
"lodash@^4.17.15":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-vzyG1a5x+...

"react@^17.0.0":
  version "17.0.2"
  resolved "https://registry.yarnpkg.com/react/-/react-17.0.2.tgz"
  integrity sha512-abc123...
  dependencies:
    "object-assign" "^4.1.1"
"""

# Mock vulnerabilities data
vulnerabilities_data = {
    "lodash": Vulnerability(
        package_name="lodash",
        versions=["4.17.21", "^4.17.0"]  # Includes caret range
    ),
    "react": Vulnerability(
        package_name="react",
        versions=["17.0.1"]  # React 17.0.2 is not vulnerable
    )
}


class TestPackageParsingAndVulnerabilities(unittest.TestCase):
    TEST_DIR = "./test_repo"

    @classmethod
    def setUpClass(cls):
        """
        Create the test directory before running tests.
        """
        os.makedirs(cls.TEST_DIR, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        """
        Clean up the test directory after tests are complete.
        """
        for file_name in os.listdir(cls.TEST_DIR):
            file_path = os.path.join(cls.TEST_DIR, file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
        if os.path.exists(cls.TEST_DIR):
            os.rmdir(cls.TEST_DIR)

    def setUp(self):
        """
        Ensure the test directory is clean before each test.
        """
        for file_name in os.listdir(self.TEST_DIR):
            file_path = os.path.join(self.TEST_DIR, file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

    def test_yarn_package_parsing(self):
        """
        Test parsing of Yarn yarn.lock.
        """
        # Write the Yarn lock file
        yarn_lock_path = os.path.join(self.TEST_DIR, "yarn.lock")
        with open(yarn_lock_path, "w", encoding="utf-8") as yarn_file:
            yarn_file.write(yarn_lock_data)

        # Run the test
        packages = get_packages_in_repo(self.TEST_DIR)
        self.assertEqual(len(packages), 3)  # lodash + react + object-assign

        # Check lodash
        lodash = next(p for p in packages if p.package_name == "lodash")
        self.assertEqual(lodash.version, "4.17.21")

        # Check react
        react = next(p for p in packages if p.package_name == "react")
        self.assertEqual(react.version, "17.0.2")
        self.assertEqual(len(react.dependencies), 1)  # object-assign

        # Check object-assign (dependency of react)
        object_assign = next(
            p for p in packages if p.package_name == "object-assign")
        self.assertEqual(object_assign.version, "^4.1.1")

    def test_yarn_vulnerability_detection_with_caret(self):
        """
        Test vulnerability detection in Yarn yarn.lock with caret versions.
        """
        # Write the Yarn lock file
        yarn_lock_path = os.path.join(self.TEST_DIR, "yarn.lock")
        with open(yarn_lock_path, "w", encoding="utf-8") as yarn_file:
            yarn_file.write(yarn_lock_data)

        # Run vulnerability detection
        report = find_vulnerabilities_in_repo(
            self.TEST_DIR, vulnerabilities_data)
        # lodash is vulnerable due to caret range
        self.assertEqual(len(report.vulnerabilities), 1)

        # Check vulnerable package
        vulnerable_package = report.vulnerabilities[0]
        self.assertEqual(vulnerable_package.package_name, "lodash")
        self.assertEqual(vulnerable_package.version, "4.17.21")

    def test_npm_package_parsing(self):
        """
        Test parsing of NPM package-lock.json.
        """
        # Write the NPM lock file
        npm_lock_path = os.path.join(self.TEST_DIR, "package-lock.json")
        with open(npm_lock_path, "w", encoding="utf-8") as npm_file:
            json.dump(npm_lock_data, npm_file, indent=2)

        # Run the test
        packages = get_packages_in_repo(self.TEST_DIR)
        self.assertEqual(len(packages), 3)  # Root package + lodash + react

        # Check root package
        root_package = next(
            p for p in packages if p.package_name == "test-project")
        self.assertEqual(root_package.version, "1.0.0")
        self.assertEqual(len(root_package.dependencies), 2)  # lodash and react

        # Check lodash
        lodash = next(p for p in packages if p.package_name == "lodash")
        self.assertEqual(lodash.version, "4.17.21")

        # Check react
        react = next(p for p in packages if p.package_name == "react")
        self.assertEqual(react.version, "17.0.2")

    def test_npm_vulnerability_detection_with_caret(self):
        """
        Test vulnerability detection in NPM package-lock.json with caret versions.
        """
        # Write the NPM lock file
        npm_lock_path = os.path.join(self.TEST_DIR, "package-lock.json")
        with open(npm_lock_path, "w", encoding="utf-8") as npm_file:
            json.dump(npm_lock_data, npm_file, indent=2)

        # Run vulnerability detection
        report = find_vulnerabilities_in_repo(
            self.TEST_DIR, vulnerabilities_data)
        # lodash is vulnerable due to caret range
        self.assertEqual(len(report.vulnerabilities), 1)

        # Check vulnerable package
        vulnerable_package = report.vulnerabilities[0]
        self.assertEqual(vulnerable_package.package_name, "lodash")
        self.assertEqual(vulnerable_package.version, "4.17.21")


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


    def test_package_json_vulnerability_detection(self):
        """
        Test that a vulnerable package listed in package.json is flagged by name.
        Version is not checked for package.json sources.
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
        # Lock file: lodash 4.17.21 (vulnerable by version)
        npm_lock_data_local = {
            "name": "test-project",
            "version": "1.0.0",
            "packages": {
                "": {
                    "name": "test-project",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "^4.17.15"}
                },
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }
        npm_lock_path = os.path.join(self.TEST_DIR, "package-lock.json")
        with open(npm_lock_path, "w", encoding="utf-8") as f:
            json.dump(npm_lock_data_local, f, indent=2)

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


if __name__ == "__main__":
    unittest.main()
