# Contributing

## Build and test

```sh
cargo build                      # target/debug/wirust
cargo test --workspace           # offline: in-process servers and clients on loopback
```

Rust 1.88 or newer and a C compiler (aws-lc-rs, the TLS crypto provider, compiles C). The
first build fetches the `fingerprint` crate from https://github.com/dec0iiyy/mirrust.

## Gates

Every change passes what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check                                        # licences, advisories, sources
python3 .github/scripts/third-party-licenses.py --check # after a Cargo.lock change, rerun without --check
.github/scripts/test-install.sh                         # after a change to install.sh
```

`cargo +1.88 check --workspace --all-targets --locked` checks the minimum Rust version.

## Where code goes

[docs/architecture.md](docs/architecture.md) has the module map and the extension seams: UI
files in `crates/proxy/ui/` (listed in `control::ASSETS`, no inline scripts or styles), API
routes in a feature's own `*_api.rs` called from `control::module_routes`, interceptors
registered in `main.rs::register_interceptors`, and query fields in `query.rs`.

### Adding a rule kind

1. Add a variant to `ActionConfig` in `rules.rs` (it is the TOML and JSON shape, tagged by
   `type`) and its compiled form in the `compile` match next to it. Validate there: a rule
   set that does not compile is refused as a whole.
2. Make the right interceptor stage of `Rules::interceptors` act on it (request, response or
   body).
3. Show it in the rules panel summary (`ui/panels.js`).
4. Add a test in `crates/proxy/tests/rules.rs` and a row and an example in
   [docs/rules.md](docs/rules.md).

## Conventions

- Tests stay offline, use random loopback ports and keep their CA in a temporary directory.
- No `unsafe` (the workspace forbids it), no `unwrap` outside tests, public items documented.
- Documentation states only what the code does; check every flag, route and limit against
  the code before you write it down.
- Commit messages: a plain imperative first line, the why in the body when it is not obvious.

Contributions are accepted under GPL-3.0-only, the licence of the project.
