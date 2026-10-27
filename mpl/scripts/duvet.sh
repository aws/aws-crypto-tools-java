#!/usr/bin/env bash
# Builds the Duvet specification-compliance report for the native Java MPL
# and prints per-specification coverage counts.
#
# Requires duvet (`cargo install duvet`), python3, and the specification
# submodule (`git submodule update --init spec` at the repository root).
# Output: mpl/.duvet/reports/report.html and report.json.
#
# duvet fails when an annotation names a missing section or quotes text the
# specification does not contain; uncited requirements do not fail the run.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f spec/framework/structures.md ]; then
  echo "error: specification missing; run 'git submodule update --init spec' at the repository root" >&2
  exit 1
fi

rm -rf .duvet/reports .duvet/requirements
duvet report

# A requirement counts once per annotation type that touches it;
# "none" counts requirements with no citation, implication, test, or exception.
python3 - .duvet/reports/report.json <<'EOF'
import collections, json, sys

report = json.load(open(sys.argv[1]))
kinds = ('citation', 'implication', 'test', 'exception')
fmt = '%-48s %5s %5s %5s %5s %5s %5s'
print(fmt % ('specification', 'reqs', 'cite', 'impl', 'test', 'exc', 'none'))
total = collections.Counter()
for path in sorted(report['specifications']):
    counts = collections.Counter()
    for req in report['specifications'][path]['requirements']:
        status = report['statuses'].get(str(req), {})
        hit = [k for k in kinds if status.get(k)]
        counts.update(hit + ['reqs'] + ([] if hit else ['none']))
    total.update(counts)
    name = path.split('framework/', 1)[-1]
    print(fmt % ((name,) + tuple(counts[k] for k in ('reqs',) + kinds + ('none',))))
print(fmt % (('TOTAL',) + tuple(total[k] for k in ('reqs',) + kinds + ('none',))))
EOF

echo "HTML report: $(pwd)/.duvet/reports/report.html"
