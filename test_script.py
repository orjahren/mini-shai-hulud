import unittest
import os
import json
from script import get_packages_in_repo, find_vulnerabilities_in_repo, Vulnerability, RepoVulnerabilityReport

try:
    import yaml
    _yaml_available = True
except ImportError:
    _yaml_available = False

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


# Mock pnpm-lock.yaml data (v6 format — packages keyed as name@version)
pnpm_lock_data = """\
lockfileVersion: '6.0'

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-abc123}
    dev: false

  react@17.0.2:
    resolution: {integrity: sha512-def456}
    dev: false
"""


@unittest.skipUnless(_yaml_available, "PyYAML not installed")
class TestPnpmParsing(unittest.TestCase):
    TEST_DIR = "./test_repo_pnpm"

    @classmethod
    def setUpClass(cls):
        os.makedirs(cls.TEST_DIR, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        for file_name in os.listdir(cls.TEST_DIR):
            os.remove(os.path.join(cls.TEST_DIR, file_name))
        os.rmdir(cls.TEST_DIR)

    def setUp(self):
        for file_name in os.listdir(self.TEST_DIR):
            os.remove(os.path.join(self.TEST_DIR, file_name))

    def _write_lock(self):
        with open(os.path.join(self.TEST_DIR, "pnpm-lock.yaml"), "w") as f:
            f.write(pnpm_lock_data)

    def test_pnpm_package_parsing(self):
        self._write_lock()
        packages = get_packages_in_repo(self.TEST_DIR)
        self.assertEqual(len(packages), 2)

        names = {p.package_name for p in packages}
        self.assertIn("lodash", names)
        self.assertIn("react", names)

        lodash = next(p for p in packages if p.package_name == "lodash")
        self.assertEqual(lodash.version, "4.17.21")

        react = next(p for p in packages if p.package_name == "react")
        self.assertEqual(react.version, "17.0.2")

    def test_pnpm_vulnerability_detection(self):
        self._write_lock()
        report = find_vulnerabilities_in_repo(self.TEST_DIR, vulnerabilities_data)
        self.assertEqual(len(report.vulnerabilities), 1)

        vuln = report.vulnerabilities[0]
        self.assertEqual(vuln.package_name, "lodash")
        self.assertEqual(vuln.version, "4.17.21")

    def test_pnpm_empty_packages_section(self):
        with open(os.path.join(self.TEST_DIR, "pnpm-lock.yaml"), "w") as f:
            f.write("lockfileVersion: '6.0'\n")
        packages = get_packages_in_repo(self.TEST_DIR)
        self.assertEqual(packages, [])


if __name__ == "__main__":
    unittest.main()
