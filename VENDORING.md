# Vendored sources

KpqC builds the reference implementations directly into its static library.
The upstream revisions are recorded in `THIRD_PARTY_NOTICES.md`; files not
needed by the library, such as benchmarks and standalone test programs, are
not copied.

## Local changes

The following integration changes are intentionally maintained on top of the
recorded upstream revisions:

- All externally visible native symbols are prefixed for KpqC so that the
  static library can coexist with separately linked reference implementations.
- Reference random-number generators are replaced by `native/randombytes.c`,
  which uses the operating system and reports entropy failures to the C++ API.
- Test builds use `native/randombytes_test.c` to inject deterministic KAT
  entropy; this file is not part of the installed library.
- AIMer reports allocation failures separately, propagates entropy failures,
  stores SHA-3 contexts inline instead of terminating on allocation failure,
  and clears released SHA-3 state.
- HAETAE and SMAUG-T propagate entropy failures.
- NTRU+ propagates entropy failures and clears temporary key-generation and
  encapsulation material on both success and failure.
- Generic SHA-3 and arithmetic symbols are renamed per parameter set to avoid
  collisions between the bundled implementations.

These changes do not alter algorithm parameters or wire formats. CI checks all
1,600 records from the test-vector revision pinned in the workflow and README.

## Updating a component

1. Record the new upstream commit in `THIRD_PARTY_NOTICES.md`.
2. Replace only the source and header files required by the build.
3. Reapply the local changes listed above and review the resulting diff.
4. Update the test-vector revision if the algorithm output changed.
5. Run the Release, sanitizer, installed-package, and symbol-isolation tests.
