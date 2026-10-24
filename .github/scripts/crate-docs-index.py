#!/usr/bin/env python3
# `cargo doc` で作った crate の文書の、一覧のページを書く。rustdoc は stable では一覧を作らないので、ここで作る。
#
# 使い方: cargo metadata --no-deps --format-version 1 --locked | crate-docs-index.py 文書のフォルダー
import html
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
metadata = json.load(sys.stdin)
members = set(metadata["workspace_default_members"])
crates = sorted(
    (package["name"], package.get("description") or "", package["version"])
    for package in metadata["packages"]
    if package["id"] in members
    and any("lib" in target["kind"] for target in package["targets"])
)
missing = [name for name, _, _ in crates if not (out / name.replace("-", "_") / "index.html").is_file()]
if missing:
    sys.exit(f"文書のない crate があります: {', '.join(missing)}")

version = crates[0][2]
rows = "\n".join(
    f'      <li><a href="{name.replace("-", "_")}/index.html">{html.escape(name)}</a>'
    f"<span>{html.escape(description)}</span></li>"
    for name, description, _ in crates
)
(out / "index.html").write_text(
    f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>heika の crate</title>
  <style>
    :root {{ --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --link: #0b5cad; --line: #d1d9e0; }}
    @media (prefers-color-scheme: dark) {{
      :root {{ --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --link: #6cb6ff; --line: #30363d; }}
    }}
    body {{ margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 system-ui, sans-serif; }}
    main {{ max-width: 52rem; margin: 0 auto; padding: 2rem 16px; }}
    h1 {{ font-size: 1.6rem; margin: 0 0 .25rem; }}
    p {{ color: var(--muted); margin: 0 0 1.5rem; }}
    a {{ color: var(--link); }}
    ul {{ list-style: none; padding: 0; margin: 0; }}
    li {{ display: flex; flex-wrap: wrap; gap: .25rem 1rem; padding: .6rem 0; border-top: 1px solid var(--line); }}
    li a {{ font-family: ui-monospace, monospace; font-weight: 600; min-width: 14rem; }}
    li span {{ color: var(--muted); flex: 1 1 18rem; }}
  </style>
</head>
<body>
  <main>
    <h1>heika の crate</h1>
    <p>{html.escape(version)} の API の文書です。使い方の文書は<a href="https://github.com/HinaBlogChannel/heika">リポジトリ</a>の docs にあります。</p>
    <ul>
{rows}
    </ul>
  </main>
</body>
</html>
""",
    encoding="utf-8",
)
