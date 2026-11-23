# Releasing

`.github/workflows/release.yml` builds, tests and publishes a release. A maintainer only
bumps the version, tags and pushes.

## What a release holds

| File | What |
|---|---|
| `wirust-linux-x86_64`, `wirust-linux-aarch64` | static musl binaries, any distribution |
| `wirust-macos-arm64`, `wirust-macos-x86_64` | macOS binaries (not signed or notarized) |
| `wirust-windows-x86_64.exe` | Windows binary (not signed) |

Since 0.6.0 every binary includes the experimental WireGuard capture mode with HTTP/3 on the
client leg (the cargo feature `wireguard`, on by default; `docs/wireguard.md`). It starts
only with `wirust wireguard` and has been tested only in process on loopback, never with a
real phone or browser.
| `wirust-vX.Y.Z-<target>.tar.gz` / `.zip` | the binary with `LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES.md`, `README.md` |
| `install.sh` | the installer from the tagged commit |
| `SHA256SUMS` | a `sha256sum -c` line for each file above |

Each file in `SHA256SUMS` also gets a signed build provenance attestation.

## Cut a release

1. Check that `main` is green in CI and that `THIRD-PARTY-LICENSES.md` is current:
   `python3 .github/scripts/third-party-licenses.py --check`.
2. Set `version` in `crates/proxy/Cargo.toml`, run `cargo check` so `Cargo.lock` follows,
   and commit.
3. Optional dry run (below) on that commit.
4. Tag and push: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
5. After the release exists, run `scripts/update-manifests.sh X.Y.Z` to refresh the Scoop and
   winget manifests (see `packaging/README.md`), commit and push.
6. The workflow checks that the tag equals `v` + the package version, builds the five
   targets, runs the whole test suite for each target in the release profile, smoke-tests the
   binaries, writes `SHA256SUMS`, attests and creates the release with generated notes
   (categories in `.github/release.yml`). A tag with a hyphen (`v0.2.0-rc.1`) is a
   pre-release.

## Dry run

```sh
gh workflow run release.yml -f publish=false     # on any branch
```

The same build, test and checksum jobs run; nothing is published, no attestation is made,
and the files are kept as workflow artifacts (`release-files`) for 7 days, named after the
commit (`dev-<sha7>`). Download them with `gh run download <run-id> -n release-files`.
Running with `publish=true` publishes only when started on a `v*` tag.

## What is verified, and what is not

Verified on every release run: the binaries build with `--locked` from a clean checkout
without a cache; the test suite passes for each target (macOS x86_64 under Rosetta 2); the
Linux binaries are static; on Linux and macOS `.github/scripts/smoke-test.sh` starts the
release binary, creates a CA, proxies a request to a local origin, serves
`http://wirust.test/` and checks the API token; on Windows the binary starts and creates its
CA. On all three systems `wirust wireguard add-peer` must print a client configuration, which
proves the WireGuard mode is in the binary. CI tests `install.sh` against a fake local release (`.github/scripts/test-install.sh`).

Not verified: the macOS and Windows binaries are not code-signed, so Gatekeeper and
SmartScreen warn on first start; nothing runs on a real phone; HTTPS interception of real
browsers is checked by hand only. `test-install.sh --online` installs a published release
and is run by hand after the first release.

## Network

The build fetches crates from crates.io and the `fingerprint` crate from the public
repository https://github.com/dec0iiyy/mirrust at the commit `Cargo.lock` pins (tag v0.1.6),
in the "Fetch the dependencies" step, without credentials. Offline, a build works only when
`cargo fetch --locked` ran before with network; then `cargo build --offline --locked`
succeeds from the local cargo cache.

## Verify a download

```sh
grep ' wirust-linux-x86_64$' SHA256SUMS | sha256sum -c -    # macOS: shasum -a 256 -c -
gh attestation verify wirust-linux-x86_64 --repo dec0iiyy/wirust \
  --signer-workflow dec0iiyy/wirust/.github/workflows/release.yml
```

The checksum shows that the download is intact; the attestation shows that this
repository's release workflow built it.
