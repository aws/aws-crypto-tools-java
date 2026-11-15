#!/usr/bin/env python3
"""Lists the Gradle modules that CI checks, as GitHub Actions outputs.

A module is a build that the root settings.gradle.kts includes with
includeBuild("<dir>"). Every CI gate runs once per module, so a new library
gets every gate by being included at the root.

Outputs (written to $GITHUB_OUTPUT when set, and printed):
  modules       JSON list of module directories, or ["(none)"] when there are
                none, so a matrix job still runs and says so
  code_modules  the modules with Java files under src/main/java
  duvet_modules the modules with a .duvet/config.toml
  test_servers  the modules with a test-server directory
"""

import json
import os
import re
import sys


def modules(root):
    with open(os.path.join(root, "settings.gradle.kts")) as f:
        settings = f.read()
    return sorted(re.findall(r'^\s*includeBuild\(\s*"([^"]+)"\s*\)', settings, re.M))


def java_files(directory):
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in ("build", ".gradle")]
        if "/src/main/java/" in dirpath.replace(os.sep, "/") + "/" and any(n.endswith(".java") for n in filenames):
            return True
    return False


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    found = modules(root)
    outputs = {
        "modules": found or ["(none)"],
        "code_modules": [m for m in found if java_files(os.path.join(root, m))],
        "duvet_modules": [m for m in found if os.path.isfile(os.path.join(root, m, ".duvet", "config.toml"))],
        "test_servers": [m for m in found if os.path.isdir(os.path.join(root, m, "test-server"))],
    }
    lines = ["%s=%s" % (name, json.dumps(value)) for name, value in outputs.items()]
    print("\n".join(lines))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
