<!-- CorvidLabs trust toolchain: BEGIN (managed, do not edit inside) -->
## CorvidLabs trust toolchain

- Use SpecSync 5 for canonical specifications and the verified SDD change lifecycle.
- Run `specsync check --strict --require-coverage 100 --force` before handing off changes; the active AlgoChat contract requires complete source and export coverage.
- Keep Claude, Cursor, Codex, and Gemini integrations installed and verify them with `specsync agents status`.
- Treat `.trust.toml` as the policy authority and run `fledge trust doctor` plus `fledge trust verify`.
- Preserve AlgoChat wire formats, cryptographic vectors, and cross-implementation compatibility tests.
- Do not approve or close an SDD change on behalf of a human owner.
<!-- CorvidLabs trust toolchain: END (managed, do not edit inside) -->
