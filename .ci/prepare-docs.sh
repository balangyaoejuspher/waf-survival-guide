#!/usr/bin/env bash
# Stage root-level community files into docs/ for MkDocs (which requires
# docs_dir to be a child directory). All copies are gitignored.
set -euo pipefail

mkdir -p docs/_root

# Homepage: README at the root of the site.
cp -f README.md docs/index.md

# Other community files under /project/ tab in the nav.
cp -f EXCEPTIONS.md      docs/_root/EXCEPTIONS.md
cp -f CONTRIBUTING.md    docs/_root/CONTRIBUTING.md
cp -f CODE_OF_CONDUCT.md docs/_root/CODE_OF_CONDUCT.md
cp -f SECURITY.md        docs/_root/SECURITY.md
cp -f LICENSE            docs/_root/LICENSE.md

# Rewrite relative links so they resolve under docs/.
python3 - <<'PY'
import re, pathlib

p = pathlib.Path("docs/index.md")
s = p.read_text(encoding="utf-8")
# Links of the form  docs/foo/bar.md  -> foo/bar.md  (since docs/ IS the docs_dir)
s = re.sub(r'\]\((docs/)', '](', s)
# EXCEPTIONS.md (root) -> _root/EXCEPTIONS.md
s = re.sub(r'\]\(EXCEPTIONS\.md\)', '](_root/EXCEPTIONS.md)', s)
# LICENSE (root, no extension) -> _root/LICENSE.md
s = re.sub(r'\]\(LICENSE\)', '](_root/LICENSE.md)', s)
# .github/* community files -> _root/*
s = re.sub(r'\]\(\.github/CONTRIBUTING\.md\)', '](_root/CONTRIBUTING.md)', s)
s = re.sub(r'\]\(\.github/SECURITY\.md\)', '](_root/SECURITY.md)', s)
s = re.sub(r'\]\(\.github/CODE_OF_CONDUCT\.md\)', '](_root/CODE_OF_CONDUCT.md)', s)
s = re.sub(r'\]\(\.github/PULL_REQUEST_TEMPLATE\.md\)', '](_root/CONTRIBUTING.md)', s)
p.write_text(s, encoding="utf-8")
PY

echo "OK: root files staged into docs/"
