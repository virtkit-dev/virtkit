#!/usr/bin/env python3
"""A suite's outcomes as one line per test, and their comparison with a baseline.

    outcomes.py from-junit RESULTS.xml            > outcomes.txt
    outcomes.py from-log   versitygw-output.log   > outcomes.txt
    outcomes.py compare    outcomes.txt expected-failures.txt [--accept]

An outcomes line is `PASS|FAIL|SKIP<tab>test id`. The baseline lists the ids expected to
fail, one per line, `#` comments allowed. `compare` prints the counts, every failure the
baseline does not expect (the regressions, or the work still to do) and every expected
failure that passed (progress: remove it from the baseline, or `--accept` to rewrite the
baseline from this run). It exits 1 when there is a new failure, so a CI step can gate on
"no worse than the baseline" while the baseline shrinks.
"""

import re
import sys
import xml.etree.ElementTree as ET

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def from_junit(path):
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        name = case.get("name", "")
        classname = case.get("classname", "")
        test_id = f"{classname}::{name}" if classname else name
        if case.find("failure") is not None or case.find("error") is not None:
            status = "FAIL"
        elif case.find("skipped") is not None:
            status = "SKIP"
        else:
            status = "PASS"
        print(f"{status}\t{test_id}")


def from_log(path):
    """versitygw's `PASS name` / `FAIL name` / `SKIP name` lines, colours stripped."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = ANSI.sub("", line).rstrip("\n")
            m = re.match(r"(PASS|FAIL|SKIP)\s+([^:\s]+)", line)
            if m:  # a FAIL line goes on with `: <why>`, which is not part of the id
                print(f"{m.group(1)}\t{m.group(2)}")


def read_outcomes(path):
    outcomes = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            status, _, test_id = line.partition("\t")
            outcomes[test_id] = status
    return outcomes


def read_baseline(path):
    expected = set()
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    expected.add(line)
    except FileNotFoundError:
        pass
    return expected


def compare(outcomes_path, baseline_path, accept):
    outcomes = read_outcomes(outcomes_path)
    expected = read_baseline(baseline_path)
    failed = {t for t, s in outcomes.items() if s == "FAIL"}
    passed = {t for t, s in outcomes.items() if s == "PASS"}
    skipped = {t for t, s in outcomes.items() if s == "SKIP"}
    new = sorted(failed - expected)
    fixed = sorted(expected & passed)
    print(f"ran {len(outcomes)}: {len(passed)} passed, {len(failed)} failed, "
          f"{len(skipped)} skipped; baseline expects {len(expected)} failures")
    if fixed:
        print(f"\n{len(fixed)} expected failures now pass (remove them from the baseline, "
              f"or --accept):")
        for t in fixed:
            print(f"  {t}")
    if new:
        print(f"\n{len(new)} failures the baseline does not expect:")
        for t in new:
            print(f"  {t}")
    if accept:
        with open(baseline_path, "w") as f:
            f.write("# Tests expected to fail, one id per line; rewritten by run.sh --accept.\n")
            f.write("# Remove a line once the server passes its test.\n")
            for t in sorted(failed):
                f.write(t + "\n")
        print(f"\nbaseline rewritten: {baseline_path} ({len(failed)} failures)")
        return 0
    return 1 if new else 0


def main(argv):
    if len(argv) >= 3 and argv[1] == "from-junit":
        from_junit(argv[2])
    elif len(argv) >= 3 and argv[1] == "from-log":
        from_log(argv[2])
    elif len(argv) >= 4 and argv[1] == "compare":
        return compare(argv[2], argv[3], "--accept" in argv[4:])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
