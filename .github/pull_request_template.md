## What changes and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked` pass (see CONTRIBUTING.md).
- [ ] A change in behaviour has a test; tests stay offline and on loopback.
- [ ] After a `Cargo.lock` change, `THIRD-PARTY-LICENSES.md` was regenerated and `cargo deny check` passes.
- [ ] Documentation that describes the changed behaviour is updated, and every statement in it was checked against the code.
