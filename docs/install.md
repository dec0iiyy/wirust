# Install

wirust is one binary. Pick the way that fits your system; every release file is listed in
`SHA256SUMS` and carries a signed build attestation (see [Verify a download](#verify-a-download)).

## Linux and macOS

```sh
curl -fsSL https://github.com/dec0iiyy/wirust/releases/latest/download/install.sh | sh
```

The script checks the download against `SHA256SUMS` (and its build attestation when `gh` is
installed) and installs into `/usr/local/bin`, or `--prefix DIR`.

## Windows

Windows x86_64 only. Choose one.

**Scoop** ([scoop.sh](https://scoop.sh)):

```powershell
scoop install https://raw.githubusercontent.com/dec0iiyy/wirust/main/packaging/scoop/wirust.json
```

It installs the release `.zip` (`wirust.exe` plus the licence files) and puts `wirust` on
your PATH. Scoop checks the download against the SHA-256 in the manifest, which comes from
the release's `SHA256SUMS`.

**winget:** the manifest is prepared in [packaging/winget](../packaging/winget) but is not yet
in the winget repository, so `winget install` does not find wirust yet.

**By hand:** download `wirust-windows-x86_64.exe` (the bare binary) or
`wirust-vX.Y.Z-x86_64-pc-windows-msvc.zip` from
[Releases](https://github.com/dec0iiyy/wirust/releases), and put `wirust.exe` in a folder on
your PATH.

### The Windows binary is not signed

The Windows binaries carry no code-signing certificate. When you start a downloaded one for
the first time, Windows SmartScreen may show "Windows protected your PC". That is the
warning for an unsigned program from a publisher Windows does not know; it does not say that
the file is harmful, and it does not say that it is safe either. To continue, choose
**More info**, then **Run anyway**. Do that only after you have checked the file as below.

## From source

```sh
cargo build --release      # Rust 1.88+, a C compiler
```

## Verify a download

Download `SHA256SUMS` next to the file. With the GitHub CLI:

```powershell
gh release download v0.5.0 -R dec0iiyy/wirust -p SHA256SUMS -p wirust-windows-x86_64.exe
```

**Checksum.** The checksum shows that the file is intact.

```powershell
Get-FileHash .\wirust-windows-x86_64.exe -Algorithm SHA256   # Windows PowerShell
Select-String 'wirust-windows-x86_64.exe' .\SHA256SUMS       # the two hashes must be equal; case does not matter
```

```sh
grep ' wirust-linux-x86_64$' SHA256SUMS | sha256sum -c -     # Linux; macOS: shasum -a 256 -c -
```

**Attestation.** The attestation shows that this repository's release workflow built the
file. It needs the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify wirust-windows-x86_64.exe --repo dec0iiyy/wirust \
  --signer-workflow dec0iiyy/wirust/.github/workflows/release.yml
```

The command exits with status 0 when the file matches an attestation of that workflow, and
with an error otherwise.
