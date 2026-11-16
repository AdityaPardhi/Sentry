#!/usr/bin/env python3
"""Convert Atomic Red Team YAML (Linux sh/bash tests) into .sh files. Does NOT run anything.
Usage: python3 yaml2sh.py T1003.008.yaml outdir/
"""
import re, sys, os, yaml

def main(src, outdir):
    os.makedirs(outdir, exist_ok=True)
    doc = yaml.safe_load(open(src, encoding="utf-8"))
    tech = doc.get("attack_technique", os.path.splitext(os.path.basename(src))[0])
    n = 0
    for i, t in enumerate(doc.get("atomic_tests", []), 1):
        ex = t.get("executor") or {}
        if "linux" not in t.get("supported_platforms", []) or ex.get("name") not in ("sh", "bash"):
            continue
        cmd = ex.get("command") or ""
        for k, v in (t.get("input_arguments") or {}).items():       # fill #{arg} with defaults
            cmd = cmd.replace("#{%s}" % k, str(v.get("default", "")))
        slug = re.sub(r"[^a-z0-9]+", "_", t.get("name", "test").lower()).strip("_")[:50]
        path = os.path.join(outdir, f"{tech}_{i}_{slug}.sh")
        shebang = "#!/bin/bash" if ex["name"] == "bash" else "#!/bin/sh"
        with open(path, "w") as f:
            f.write(f"{shebang}\n# {tech} test {i}: {t.get('name')}\n"
                    f"# elevation_required: {ex.get('elevation_required', False)}\n{cmd.rstrip()}\n")
        os.chmod(path, 0o755); n += 1
        print("wrote", path)
    print(f"{n} script(s) created. Read each one before running.")

if __name__ == "__main__":
    if len(sys.argv) != 3: sys.exit(__doc__)
    main(*sys.argv[1:])