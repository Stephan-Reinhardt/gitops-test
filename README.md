!/usr/bin/env python3
"""Check the tenant's Kustomize folders for typos that kustomize does not catch.

Only uses the Python standard library: runs on Linux and Windows (Python 3.6+),
without kustomize or PyYAML.

    python ci/check-refs.py                         # every gitops/<ns>/<cluster>/ folder
    python ci/check-refs.py gitops/kc-client-a/crc  # one folder

For each folder it follows resources:, components: and patches: the way
kustomize does and reports:
  - files or folders that are listed but do not exist (also case mismatches,
    which Windows hides)
  - YAML files in a component folder that its kustomization.yaml does not list
  - serviceAccountName values without a ServiceAccount of that name in the
    same build ("serviceaccount ... not found" in Argo CD)
  - misspelled kinds and kustomization keys, tabs, non-ASCII characters
The parser is deliberately simple: it reads the block style used in this repo.
"""
import difflib
import os
import re
import sys

KINDS = {
    "ConfigMap", "CronJob", "Deployment", "Job", "Kustomization", "Component",
    "NetworkPolicy", "PersistentVolumeClaim", "PodDisruptionBudget", "Role",
    "RoleBinding", "Route", "Secret", "SealedSecret", "Service", "ServiceAccount",
    "StatefulSet", "Cluster", "HorizontalPodAutoscaler", "ServiceMonitor",
    "PodMonitor", "LimitRange", "ResourceQuota", "Namespace",
}
KUSTOMIZE_KEYS = {
    "apiVersion", "kind", "namespace", "namePrefix", "nameSuffix", "labels",
    "commonLabels", "commonAnnotations", "resources", "components", "patches",
    "patchesStrategicMerge", "patchesJson6902", "images", "replacements",
    "configMapGenerator", "secretGenerator", "generatorOptions", "replicas",
    "generators", "transformers", "validators", "openapi", "crds", "buildMetadata",
    "sortOptions", "helmCharts", "vars",
}
KUSTOMIZATION_FILES = ("kustomization.yaml", "kustomization.yml", "Kustomization")

problems = []


def problem(path, msg):
    problems.append("%s: %s" % (os.path.relpath(path), msg))


def strip_comment(line):
    """Remove a '# comment' that is not inside quotes."""
    quote = None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def read_lines(path):
    with open(path, encoding="utf-8") as f:
        raw = f.read().splitlines()
    out = []
    for n, line in enumerate(raw, 1):
        if "\t" in line:
            problem(path, "line %d: tab character (YAML allows spaces only)" % n)
        code = strip_comment(line)
        bad = [c for c in code if ord(c) > 127]
        if bad:
            problem(path, "line %d: non-ASCII character(s) %r outside a comment" % (n, "".join(bad)))
        out.append((n, code))
    return out


def documents(path):
    """Yield (first line number, [(n, line), ...]) per '---' document."""
    doc, start = [], 1
    for n, line in read_lines(path):
        if line.strip() == "---" or line.startswith("--- "):
            if any(l.strip() for _, l in doc):
                yield start, doc
            doc, start = [], n + 1
        else:
            doc.append((n, line))
    if any(l.strip() for _, l in doc):
        yield start, doc


def summarize(doc):
    """kind, metadata.name, metadata.namespace, serviceAccountName refs, top-level keys."""
    info = {"kind": None, "name": None, "namespace": None, "sa_refs": [], "keys": {}}
    in_metadata = False
    for n, line in doc:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        m = re.match(r"^([A-Za-z0-9_.-]+):\s*(.*)$", line.strip())
        if indent == 0 and m:
            info["keys"][m.group(1)] = n
            in_metadata = m.group(1) == "metadata"
            if m.group(1) == "kind":
                info["kind"] = unquote(m.group(2))
            if in_metadata and m.group(2).startswith("{"):     # metadata: { name: x }
                for k, v in re.findall(r"(\w+):\s*([^,}]+)", m.group(2)):
                    if k in ("name", "namespace"):
                        info[k] = unquote(v)
            continue
        if in_metadata and indent == 2 and m and m.group(1) in ("name", "namespace"):
            info[m.group(1)] = unquote(m.group(2))
        sa = re.search(r"\bserviceAccountName:\s*(\S+)", line)
        if sa:
            info["sa_refs"].append((n, unquote(sa.group(1).rstrip(",}"))))
        for typo in ("serviceAccount:", "serviceaccountName:", "ServiceAccountName:", "serviceAcountName:"):
            if line.strip().startswith(typo):
                problem_line = "line %d: '%s' - did you mean 'serviceAccountName:'?" % (n, typo)
                info.setdefault("typos", []).append(problem_line)
    return info


def list_items(doc, key):
    """Entries of a top-level list: '- x', '- path: x' (patches) or 'key: [a, b]'.
    Deeper lines (inline patches, target: blocks) are skipped."""
    items, inside, item_indent = [], False, None
    for n, line in doc:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and not line.startswith("-"):
            m = re.match(r"^%s:\s*(.*)$" % re.escape(key), line)
            inside, item_indent = bool(m), None
            if m and m.group(1).startswith("["):
                items += [(n, unquote(x)) for x in m.group(1).strip("[]").split(",") if x.strip()]
                inside = False
            continue
        if not inside:
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            if item_indent is None:
                item_indent = indent
            if indent != item_indent:
                continue
            value = stripped[2:].strip()
            if value.startswith("path:"):
                items.append((n, unquote(value[5:])))
            elif key != "patches" and not re.match(r"^[\w.-]+:(\s|$)", value):
                items.append((n, unquote(value)))
        elif key == "patches" and item_indent is not None and indent == item_indent + 2 \
                and stripped.startswith("path:"):
            items.append((n, unquote(stripped[5:])))
    return items


def exists_exact(path):
    """True if path exists with exactly this spelling (Windows ignores case)."""
    if not os.path.exists(path):
        return False
    parent, name = os.path.split(os.path.abspath(path))
    return name in os.listdir(parent)


def kustomization_file(folder):
    for f in KUSTOMIZATION_FILES:
        p = os.path.join(folder, f)
        if exists_exact(p):
            return p
    return None


class Build:
    def __init__(self):
        self.objects = []          # (kind, name, namespace, file, line)
        self.sa_refs = []          # (name, file, line, workload kind, workload name)
        self.seen = set()

    def add_file(self, path):
        for start, doc in documents(path):
            info = summarize(doc)
            for t in info.get("typos", []):
                problem(path, t)
            kind = info["kind"]
            if kind is None:
                problem(path, "line %d: document without 'kind:'" % start)
                continue
            if kind not in KINDS:
                close = difflib.get_close_matches(kind, KINDS, 1, 0.75)
                if close:
                    problem(path, "line %d: kind '%s' - did you mean '%s'?" % (start, kind, close[0]))
            if not info["name"] and kind not in ("Kustomization", "Component"):
                problem(path, "line %d: %s without metadata.name (check the indentation under metadata:)"
                        % (start, kind))
            self.objects.append((kind, info["name"], info["namespace"], path, start))
            for n, ref in info["sa_refs"]:
                self.sa_refs.append((ref, path, n, kind, info["name"]))

    def add_folder(self, folder, as_component=False):
        folder = os.path.normpath(folder)
        if folder in self.seen:
            return
        self.seen.add(folder)
        kfile = kustomization_file(folder)
        if not kfile:
            problem(folder, "no kustomization.yaml in this folder")
            return
        doc = [l for _, d in documents(kfile) for l in d]
        info = summarize(doc)
        for key, n in info["keys"].items():
            if key not in KUSTOMIZE_KEYS:
                close = difflib.get_close_matches(key, KUSTOMIZE_KEYS, 1, 0.7)
                hint = " - did you mean '%s'?" % close[0] if close else ""
                problem(kfile, "line %d: unknown key '%s'%s" % (n, key, hint))
        want = "Component" if as_component else "Kustomization"
        if info["kind"] != want:
            problem(kfile, "kind is '%s', but it is used as a %s (kind: %s)" % (info["kind"], want.lower(), want))

        listed = set()
        for key in ("resources", "components", "patches"):
            for n, entry in list_items(doc, key):
                if "://" in entry or entry.startswith("github.com/"):
                    continue
                target = os.path.normpath(os.path.join(folder, entry))
                listed.add(target)
                if not exists_exact(target):
                    hint = ""
                    if os.path.exists(target):
                        hint = " (exists with a different upper/lower case)"
                    else:
                        parent = os.path.dirname(target)
                        if os.path.isdir(parent):
                            close = difflib.get_close_matches(os.path.basename(target), os.listdir(parent), 1, 0.6)
                            if close:
                                hint = " - did you mean '%s'?" % close[0]
                    problem(kfile, "line %d: %s '%s' not found%s" % (n, key, entry, hint))
                    continue
                if os.path.isdir(target):
                    self.add_folder(target, as_component=(key == "components"))
                elif key != "patches":
                    self.add_file(target)

        # YAML next to a component's kustomization.yaml that nothing lists
        if as_component:
            for f in sorted(os.listdir(folder)):
                p = os.path.normpath(os.path.join(folder, f))
                if f.endswith((".yaml", ".yml")) and p != os.path.normpath(kfile) and p not in listed:
                    problem(p, "not listed in %s (resources:/patches:), so it is not deployed"
                            % os.path.relpath(kfile))

    def check(self, root):
        sas = {}
        for kind, name, ns, path, line in self.objects:
            if kind == "ServiceAccount" and name:
                sas[name] = (ns, path)
        for ref, path, line, kind, wname in self.sa_refs:
            if ref not in sas:
                close = difflib.get_close_matches(ref, sas, 1, 0.6)
                hint = " - did you mean '%s'?" % close[0] if close else ""
                problem(path, "line %d: %s %s uses serviceAccountName '%s', but this build has no "
                              "ServiceAccount of that name%s (ServiceAccounts: %s)"
                        % (line, kind, wname, ref, hint, ", ".join(sorted(sas)) or "none"))
            else:
                wns = next((o[2] for o in self.objects if o[0] == kind and o[1] == wname), None)
                if sas[ref][0] and wns and sas[ref][0] != wns:
                    problem(sas[ref][1], "ServiceAccount %s is in namespace '%s', %s %s in '%s'"
                            % (ref, sas[ref][0], kind, wname, wns))


def targets(args, root):
    if args:
        return args
    gitops = os.path.join(root, "gitops")
    found = []
    for dirpath, _, files in os.walk(gitops):
        depth = os.path.relpath(dirpath, gitops).count(os.sep)
        if depth == 1 and os.path.basename(dirpath) != "common" and any(f in files for f in KUSTOMIZATION_FILES):
            found.append(dirpath)
    return sorted(found)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    folders = targets(sys.argv[1:], root)
    if not folders:
        print("no gitops/<ns>/<cluster>/ folders found under %s" % root)
        return 1
    total = 0
    for folder in folders:
        problems.clear()
        b = Build()
        b.add_folder(folder)
        b.check(root)
        msgs = sorted(set(problems))
        total += len(msgs)
        print("%s %s" % ("OK  " if not msgs else "FAIL", os.path.relpath(folder)))
        for m in msgs:
            print("     " + m)
    print("\n%d problem(s)" % total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
