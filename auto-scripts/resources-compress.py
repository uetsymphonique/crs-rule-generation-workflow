#!/usr/bin/env python3
# resources-compress.py - stage + zip the small review artifacts per CVE for handoff
#
# Split out of reviewer.py (which got too large). For handoff to the
# content/purple team, staging the full out/<id>/ tree per CVE is too heavy
# (claude-step*.log/.raw.json are the raw multi-turn transcripts, tens-hundreds
# of KB each). This copies only the small result artifacts (verdict.json,
# probe.json, probe-input.json, new.json, extended-requests.json,
# variant-handoff.json, verify-candidate.conf, verify-report.json - whichever
# exist per CVE) into --resources-dir and zips it to --resources-zip.
#
# Usage (from repo root, using the project venv):
#   venv/Scripts/python.exe auto-scripts/resources-compress.py
#   venv/Scripts/python.exe auto-scripts/resources-compress.py --out-dir out --resources-zip handoff.zip

import argparse
import shutil
import zipfile
from pathlib import Path

# Small, review-relevant artifacts - excludes claude-step*.log/.raw.json (raw
# debug transcripts) and *-context.json (intermediate, redundant with verdict.json).
DEFAULT_RESOURCE_FILES = [
    "verdict.json",
    "probe.json",
    "probe-input.json",
    "new.json",
    "extended-requests.json",
    "variant-handoff.json",
    "verify-candidate.conf",
    "verify-report.json",
]


def build_resources_archive(verdict_paths, file_names, staging_dir: Path, zip_path: str, keep_staging: bool):
    # PoC payloads in verdict.json/new.json (webshells, shellcode-like byte
    # patterns) can get flagged and silently quarantined by antivirus the
    # instant they're written to a new location - copy2/zf.write are wrapped
    # per-file so one quarantined artifact doesn't abort the whole batch.
    if staging_dir.exists():
        shutil.rmtree(staging_dir, ignore_errors=True)
    staging_dir.mkdir(parents=True, exist_ok=True)

    cves_seen = set()
    copied = []  # (cve_id, filename, dest_path) for direct zipfile.write below
    skipped = []  # (cve_id, filename, error) - e.g. AV-quarantined mid-copy
    for vp in verdict_paths:
        cve_dir = vp.parent
        for fname in file_names:
            src = cve_dir / fname
            if not src.exists():
                continue
            dest = staging_dir / cve_dir.name
            dest.mkdir(parents=True, exist_ok=True)
            dst = dest / fname
            try:
                shutil.copy2(src, dst)
                copied.append((cve_dir.name, fname, dst))
                cves_seen.add(cve_dir.name)
            except OSError as e:
                skipped.append((cve_dir.name, fname, str(e)))

    zip_path = str(zip_path)
    if not zip_path.lower().endswith(".zip"):
        zip_path += ".zip"
    # Write directly with arcnames (rather than shutil.make_archive, which
    # chdir()s into staging_dir internally and can choke on some Windows paths).
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for cve_id, fname, dst in copied:
            try:
                zf.write(dst, arcname=f"{cve_id}/{fname}")
            except OSError as e:
                skipped.append((cve_id, fname, str(e)))

    if not keep_staging:
        shutil.rmtree(staging_dir, ignore_errors=True)

    return zip_path, len(cves_seen), len(copied), skipped


def main():
    parser = argparse.ArgumentParser(description="Stage + zip review-relevant CRS pipeline artifacts per CVE")
    parser.add_argument("--out-dir", default="out", help="Directory holding <id>/verdict.json (default: out)")
    parser.add_argument("--resources-dir", default="cve-resources",
                        help="Staging folder for copied artifacts (default: cve-resources)")
    parser.add_argument("--resources-zip", default=None,
                        help="Output .zip path (default: <resources-dir>.zip)")
    parser.add_argument("--resources-files", default=None,
                        help="Comma-separated file names to copy per CVE "
                             "(default: verdict/probe/new/extended-requests/variant-handoff/verify-*)")
    parser.add_argument("--keep-staging", action="store_true",
                        help="Keep the staging folder after zipping (default: delete it, zip only)")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    verdict_paths = sorted(out_dir.glob("*/verdict.json"))
    total = len(verdict_paths)

    file_names = (
        [f.strip() for f in args.resources_files.split(",") if f.strip()]
        if args.resources_files else DEFAULT_RESOURCE_FILES
    )
    zip_target = args.resources_zip or f"{args.resources_dir}.zip"
    archive_path, n_cves, n_files, skipped = build_resources_archive(
        verdict_paths, file_names, Path(args.resources_dir), zip_target, args.keep_staging,
    )
    print(f"resources archive: {n_files} file(s) across {n_cves}/{total} CVE(s) -> {archive_path}"
          + ("" if args.keep_staging else f" (staging dir {args.resources_dir}/ removed)"))
    if skipped:
        print(f"  WARNING: {len(skipped)} file(s) skipped (often antivirus quarantining PoC payloads on copy):")
        for cve_id, fname, err in skipped:
            print(f"    {cve_id}/{fname}: {err}")


if __name__ == "__main__":
    main()
