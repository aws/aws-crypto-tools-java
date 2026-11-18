#!/usr/bin/env python3
"""Turns JaCoCo XML reports into one lcov file with line (DA) and branch (BRDA) records.

Usage: jacoco_lcov.py <module dir> <out.lcov> <jacocoTestReport.xml>...

SF paths are relative to the repository root (the working directory), found
by looking up each <sourcefile> under the module's src/main/java directories.
JaCoCo counts branches per line without naming them, so a line with mb missed
and cb covered branches gets cb taken and mb untaken BRDA records. Prints the
line and branch totals.
"""

import glob
import os
import sys
import xml.etree.ElementTree as ElementTree


def source_roots(module):
    return sorted(d for d in glob.glob(os.path.join(module, "**", "src", "main", "java"), recursive=True)
                  if "/build/" not in d.replace(os.sep, "/"))


def convert(module, reports):
    roots = source_roots(module)
    records, totals = [], {"lines": [0, 0], "branches": [0, 0]}
    for report in reports:
        for package in ElementTree.parse(report).getroot().iter("package"):
            for sourcefile in package.findall("sourcefile"):
                relative = os.path.join(package.get("name"), sourcefile.get("name"))
                path = next((os.path.join(r, relative) for r in roots if os.path.isfile(os.path.join(r, relative))), None)
                if path is None:
                    raise SystemExit("no source file %s under %s" % (relative, ", ".join(roots) or module))
                out = ["SF:%s" % path.replace(os.sep, "/")]
                for line in sourcefile.findall("line"):
                    number, ci = line.get("nr"), int(line.get("ci"))
                    mb, cb = int(line.get("mb")), int(line.get("cb"))
                    out.append("DA:%s,%d" % (number, 1 if ci > 0 else 0))
                    totals["lines"][0] += ci > 0
                    totals["lines"][1] += 1
                    for i in range(cb + mb):
                        out.append("BRDA:%s,0,%d,%s" % (number, i, "1" if i < cb else ("0" if ci > 0 else "-")))
                    totals["branches"][0] += cb
                    totals["branches"][1] += cb + mb
                out.append("end_of_record")
                records.append("\n".join(out))
    return "\n".join(records) + ("\n" if records else ""), totals


def main():
    module, out, reports = sys.argv[1], sys.argv[2], sys.argv[3:]
    lcov, totals = convert(module, reports)
    with open(out, "w") as f:
        f.write(lcov)
    for name, (hit, total) in totals.items():
        print("%s: %s %d of %d (%s)" % (module, name, hit, total, "%.1f%%" % (100.0 * hit / total) if total else "-"))


if __name__ == "__main__":
    main()
