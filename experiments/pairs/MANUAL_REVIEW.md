# Manual source and patch inspection — 2026-10-08

The three development pairs were chosen before location inspection:
one PyVul (`apkleaks`) and two SecBench.js (`diskusage-ng`, `dns-sync`). I inspected
the vulnerable and fixed source lines directly from the checksum-verified cache,
checked the difflib edits and omission lists, and compared the emitted locations.
This is a source inspection by the repository agent, not independent human
adjudication or an effectiveness measurement. No Semgrep/CodeQL invocation,
dependency installation for target projects, exploit execution or target-code
execution occurred.

## apkleaks

- Vulnerable archive: `07d51d7d2fb9e3ac093f5ec081517c51246d4c0becf0a81131a162f9f7a26987`.
- Fixed archive: `67b7ad92a75667764cc0a522b75e7cf6bfa094f259232a76a684b62d4f58de1f`.
- Both are GitHub TOFU; refs and original codeload URLs are preserved in the lock.
- Exactly one non-ignored file changes: `apkleaks/apkleaks.py`, with two hunks.
  The first adds the `quote` import. The second replaces old lines 87–88.
- At vulnerable line 82 the APK package name contributes to `dex`; line 87 builds
  a shell command by interpolation and line 88 calls `os.system(dec)`.
  The AST reports the call at `88:3`, ending at column 17.
- The fixed side builds an argument array at line 88, applies `quote` to each
  argument at line 89, and still calls `os.system(comm)` at line 90.
- PyVul function dataset line 646 names `decompile`. Its normalized `code_before`
  checksum exactly matches vulnerable lines 78–89, so the location is narrowed
  to that function. The dataset file and function text checksums are recorded.
- README, LICENSE and `.github/SECURITY.md` are the three omissions on each side.
- Result: one resolved vulnerable location, no unresolved case. The continued
  `os.system` call on the fixed side is not by itself a false positive.

## diskusage-ng 0.2.6 → 1.0.0

- Vulnerable archive: `216b5dcdc97b341b8e5c9fea7ce77b25d3234939e0ba4133a2c3e490c8cd1c3f`.
- Fixed archive: `09d9e11028cb8d37758e5bab0a223548d11c8207c0c072637c9a2c5f2c02bf45`.
- npm registry integrity was verified for both versions.
- Three non-ignored files change, producing four hunks. The security-relevant
  diff is `lib/posix.js`; the other changes are preserved in `patch-hunks.json`.
- Vulnerable line 3 imports `child_process.exec` as `exec`. At line 11 it inserts
  `path` into a `df -k` shell command; the earlier guard only excludes quotes.
- The published `lib/posix.js:11:5` hint matches the callee exactly. The parsed
  call extends through line 21 because it includes the callback; the locator
  validates the hint against the callee span, not arbitrary callback context.
- The fixed side imports `execFile` and at line 7 uses executable `df` with
  argument list `['-k', path]`. The obsolete quote check is removed.
- Four vulnerable and five fixed test/documentation paths are listed as omissions.
- Result: one resolved vulnerable location, no unresolved case. This inspection
  does not label the entire fixed package safe.

## dns-sync 0.1.0 → 0.1.3

- Vulnerable archive: `05c225bf536afea9103a8f4ef0f0971b208e1593cf22317d8290aad5e56cad4f`.
- Fixed archive: `a67c099624f116533924160391b5d1df2943c8261d28eb2a02fd88dfd6052a72`.
- npm registry integrity was verified for both versions.
- Six non-ignored files change, producing seven hunks. Added benchmarks, package
  metadata and DNS helper changes are preserved; none is assumed vulnerable.
- Vulnerable line 6 imports `shelljs` as `shell`. Line 19 puts `hostname` directly
  into the formatted command; line 21 calls `shell.exec`.
- The published hint `lib/dns-sync.js:21:26` points at `exec` within the callee.
  The complete call starts at `21:20` and ends at column 51. The hint is retained
  verbatim rather than rewritten to the normalized call start.
- The fixed side adds `ValidHostnameRegex` and `isValidHostName`; lines 27–30
  reject invalid hostname input before command construction. `shell.exec` remains
  at line 36. There are also new DNS-type semantics, so the diff is not reduced
  to a single sink replacement or a blanket safety conclusion.
- Three vulnerable and five fixed test/documentation paths are listed as omissions.
- Result: one resolved vulnerable location, no unresolved case.

## Preparation totals

- 51 manifests validate; 24 development, 16 held out, 11 reserve.
- 50 complete source pairs / 100 archives locked; Ray fails the 50 MiB bound on
  both sides. No reserves were promoted and no split was redrawn.
- Hunk and known-location extraction covers these **3 development pairs only**:
  13 hunks, 3 resolved locations, 0 unresolved cases. The other 48 manifests have
  not had their locations inspected; they are not counted as resolved or safe.
- **Zero vulnerability scanner invocations in this preparation.** Older recorded
  development scans remain separate; `curling`/`open` prior exposure is not erased.
