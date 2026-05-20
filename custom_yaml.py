import json
import os
from subprocess import run

DEBUG = os.environ.get("DEBUG", "") != ""

commands = {
    "go-yq": ["yq", "-o=json", "."],
    "py-yq": ["yq", "."],
}
yaml_impl = None
try:
    import yaml
    yaml_impl = "PyYAML"
except ImportError:
    for impl, cmd in commands.items():
        cp = run(cmd, input="hello: world", text=True, capture_output=True)
        if cp.returncode == 0 and json.loads(cp.stdout) == {"hello": "world"}:
            yaml_impl = impl
            break

if DEBUG:
    print(f"Using YAML parser: {yaml_impl}")

def parse_yaml(file_path):
    if yaml_impl is None:
        raise RuntimeError("No YAML parser available. Please install PyYAML or yq(1).")
    with open(file_path, 'r') as f:
        if yaml_impl == "PyYAML":
            return yaml.safe_load(f)
        elif yaml_impl in commands:
            cp = run(commands[yaml_impl], stdin=f, text=True, capture_output=True)
            if cp.returncode == 0:
                return json.loads(cp.stdout)
            raise RuntimeError(f"Error parsing YAML with yq: {cp.stderr}")

