# Packaging

Package manifests for Windows. They point at the files of a published GitHub release; they
do not build anything.

| Path | What | State |
|---|---|---|
| `scoop/wirust.json` | [Scoop](https://scoop.sh) manifest for the release `.zip`. Users install it straight from this repository: `scoop install https://raw.githubusercontent.com/dec0iiyy/wirust/main/packaging/scoop/wirust.json` | usable once it is on `main` |
| `winget/` | the three [winget](https://learn.microsoft.com/windows/package-manager/) manifest files for `dec0iiyy.wirust` (version, installer, default locale), schema 1.10.0 | prepared, **not submitted** to `microsoft/winget-pkgs` |

The Scoop manifest installs `wirust-vX.Y.Z-x86_64-pc-windows-msvc.zip` (it holds
`wirust-vX.Y.Z-x86_64-pc-windows-msvc/wirust.exe` and the licence files, hence `extract_dir`).
The winget manifest uses `InstallerType: portable` with the bare `wirust-windows-x86_64.exe`
and the command alias `wirust`. Both hashes come from the `SHA256SUMS` file of the release
(Scoop lower case, winget upper case, as each tool's manifests usually write them). The
binaries are not code-signed; see [docs/install.md](../docs/install.md).

## Refresh the manifests for a new release

After the release workflow has published `vX.Y.Z` (see [docs/releasing.md](../docs/releasing.md)):

```sh
scripts/update-manifests.sh X.Y.Z      # v0.1.1 works too
git diff packaging
```

The script downloads `SHA256SUMS` of that release with `gh release download -R dec0iiyy/wirust`
into a temporary directory and rewrites the version, the download URLs, the hashes and the
winget release date in both manifests. Run twice with the same version, it changes nothing the
second time. It fails, without touching a file, when the release or one of the two assets is
missing. It needs `gh` (logged in is enough for a public release), `jq` and `awk`. It publishes
nothing: commit the result and push it to `main`; after that the Scoop line above installs the
new version.

To check the hashes against the real files, not just against `SHA256SUMS`:

```sh
mkdir /tmp/wirust-check && cd /tmp/wirust-check
gh release download vX.Y.Z -R dec0iiyy/wirust \
  -p SHA256SUMS -p wirust-windows-x86_64.exe -p 'wirust-v*-x86_64-pc-windows-msvc.zip'
shasum -a 256 wirust-windows-x86_64.exe wirust-v*-x86_64-pc-windows-msvc.zip   # sha256sum on Linux
grep -E 'windows' SHA256SUMS                                                   # the same two hashes
```

The `checkver` and `autoupdate` entries of the Scoop manifest let Scoop's own bucket tooling
(`bin/checkver.ps1 -Update`) do the same bump; the script does it without PowerShell.

## winget: what the owner still has to do

Nothing here is submitted. To get `winget install dec0iiyy.wirust` working:

1. On Windows, check the files: `winget validate --manifest packaging\winget`.
2. Optionally install from them: `winget settings --enable LocalManifestFiles` (administrator
   prompt), then `winget install --manifest packaging\winget`. Test that `wirust --help` runs
   in a new terminal.
3. Fork `microsoft/winget-pkgs`, copy the three files to
   `manifests/d/dec0iiyy/wirust/X.Y.Z/` (the file names stay as they are), and open a pull
   request. Later versions need the same after `scripts/update-manifests.sh`; tools such as
   `wingetcreate` or `komac` can also write and submit the update.

Not tested: there is no Windows machine behind these files. They were checked for syntax and
field names only: the JSON with `jq`, the YAML parsed and compared with the 1.10.0 manifest
schemas of `microsoft/winget-cli` (required fields, types, patterns, lengths), the field names
against the schema documentation and a recent `jqlang.jq` portable manifest in `winget-pkgs`,
and the hashes against the downloaded release files. Newer schema versions exist (1.12.0 and
later); 1.10.0 is what the `jqlang.jq` 1.8.1 portable manifest in `winget-pkgs` uses.
