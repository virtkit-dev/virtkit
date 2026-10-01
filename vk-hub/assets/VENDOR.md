# Vendored web UI assets

Embedded in `vk-hub` with `include_bytes!` (`src/ui/assets.rs`) and served from the hub
itself; nothing is fetched from a CDN at runtime. Each file is exactly as published.

| File | Package | Source | sha256 | License |
|---|---|---|---|---|
| `htmx.min.js` | htmx.org 2.0.7 | https://cdn.jsdelivr.net/npm/htmx.org@2.0.7/dist/htmx.min.js | `60231ae6ba9db3825eb15a261122d5f55921c4d53b66bf637dc18b4ee27c79f9` | 0BSD (the package's `license` and `LICENSE`) |
| `sse.min.js` | htmx-ext-sse 2.2.3 | https://cdn.jsdelivr.net/npm/htmx-ext-sse@2.2.3/dist/sse.min.js | `204a17ec2bf490b7df592f55ebe547e44b099fb53c88b442d0bced0e10327e12` | 0BSD (the package's `LICENSE`; its `package.json` names none) |

Each is byte for byte the `package/dist/` file of the npm registry's tarball for its
version, whose sha512 is that version's `dist.integrity`. To update one, take the new
version's file, check it the same way, and change the version, URL and sha256 here in the
same commit.

`ui.css` is the UI's own.
