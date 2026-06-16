#!/usr/bin/env python3
"""Build compact per-file rule indexes for the crs-retrieve-analyze skill.

Why: CRS .conf rules carry machine-generated regexes up to ~12KB on a single
line. Reading those into an LLM context is the dominant token cost of the
retrieve step and is near-useless — the verdict depends on variables (scope),
operator TYPE, transforms, phase, chain-flag and msg, not the regex body.

This script extracts exactly those fields, one row per detection rule, into
`index/<fileid>.tsv`. The skill greps the index instead of the .conf files.
Re-run when the coreruleset submodule is updated.

Usage:  python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py   (from repo root)
Output: .claude/skills/crs-retrieve-analyze/index/<fileid>.tsv
"""

from __future__ import annotations
import re
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_DIR.parents[2]            # .../.claude/skills/<skill> -> repo root
RULES_DIR = REPO_ROOT / "coreruleset" / "rules"
INDEX_DIR = SKILL_DIR / "index"

COLUMNS = ["id", "file", "line", "phase", "pl", "variables", "operator", "transforms", "chain", "severity", "tags", "msg"]

# Keep only the classification-relevant tags; drop OWASP_CRS, capec, paranoia-level.
TAG_KEEP = ("attack-", "language-", "platform-", "application-")


def join_continuations(text: str) -> list[tuple[int, str]]:
    """Join physical lines ending in backslash into one logical line each.

    Returns (start_lineno, text) per logical line, where start_lineno is the
    1-based physical line on which the logical line begins (i.e. where the
    `SecRule` directive starts) — used to populate the index `line` column.
    """
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\n")
        if buf == "":
            start = i
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
        else:
            buf += line
            out.append((start, buf))
            buf = ""
    if buf:
        out.append((start, buf))
    return out


def extract_operator(line_after_vars: str) -> str:
    """Return a compact operator descriptor, dropping any @rx regex body."""
    m = re.search(r'"(!?@\w+)(?:\s+([^\s"]+))?', line_after_vars)
    if not m:
        return "@rx"  # implicit operator
    op, arg = m.group(1), m.group(2)
    # For phrase-match-from-file keep the data file; it IS the signal.
    if op.lower().endswith("pmfromfile") and arg:
        return f"{op}:{arg}"
    return op


def parse_rule(line: str) -> dict | None:
    # Top-level detection rule: starts at column 0, has an id and a msg.
    if not line.startswith("SecRule "):
        return None
    if "skipAfter" in line or "msg:" not in line:
        return None
    rid = re.search(r"\bid:(\d+)", line)
    if not rid:
        return None

    mvars = re.match(r"SecRule\s+(\S+)\s+(.*)", line)
    variables = mvars.group(1) if mvars else "?"
    operator = extract_operator(mvars.group(2) if mvars else line)

    phase = (re.search(r"\bphase:(\d+)", line) or [None, ""])[1]
    pl = (re.search(r"paranoia-level/(\d)", line) or [None, "1"])[1]
    sev = (re.search(r"severity:'([^']+)'", line) or [None, ""])[1]
    msg = (re.search(r"msg:'([^']*)'", line) or [None, ""])[1]

    tags = [t for t in re.findall(r"tag:'([^']+)'", line)
            if t.startswith(TAG_KEEP)]

    transforms = ",".join(dict.fromkeys(re.findall(r"\bt:(\w+)", line)))  # dedupe, keep order

    # chain=1 ⇒ rule has chained conditions; the index can't carry the chained
    # SecRule bodies, so INSPECT must Read the .conf block for these (and for @rx).
    chain = "1" if re.search(r",\s*chain\b", line) else "0"

    return {
        "id": rid.group(1),
        "phase": phase,
        "pl": pl,
        "variables": variables,
        "operator": operator,
        "transforms": transforms,
        "chain": chain,
        "severity": sev,
        "tags": " ".join(tags),
        "msg": msg.replace("\t", " "),
    }


def file_id(name: str) -> str | None:
    m = re.match(r"(?:REQUEST|RESPONSE)-(\d{3})-", name)
    return m.group(1) if m else None


def main() -> None:
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    total = 0
    for conf in sorted(RULES_DIR.glob("*.conf")):
        fid = file_id(conf.name)
        if not fid:
            continue
        rows = []
        for start, line in join_continuations(conf.read_text(encoding="utf-8", errors="replace")):
            r = parse_rule(line)
            if r:
                r["file"] = conf.name
                r["line"] = str(start)
                rows.append(r)
        if not rows:
            continue
        out = INDEX_DIR / f"{fid}.tsv"
        with out.open("w", encoding="utf-8", newline="\n") as f:
            f.write("# source: " + conf.name + "\t(regenerate: python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py)\n")
            f.write("\t".join(COLUMNS) + "\n")
            for r in rows:
                f.write("\t".join(r[c] for c in COLUMNS) + "\n")
        total += len(rows)
        print(f"{fid}.tsv  {len(rows):3d} rules  <- {conf.name}")
    print(f"\nTotal: {total} detection rules indexed into {INDEX_DIR}")


if __name__ == "__main__":
    main()
