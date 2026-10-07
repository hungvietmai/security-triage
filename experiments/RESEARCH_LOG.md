# Research publication log

This log records externally visible research-methodology freezes and publication evidence.

## 2026-10-05 — Amendment 03: command-injection family scope

- Amendment: `experiments/amendments/AMENDMENT_03_COMMAND_INJECTION_FAMILY.md`
- Adoption commit: `67ef4e4c1d94f71eac6ffcee06ffff353bb8790f`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/67ef4e4c1d94f71eac6ffcee06ffff353bb8790f
- Tag: `amendment-03`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/amendment-03
- Verified tag target: `67ef4e4c1d94f71eac6ffcee06ffff353bb8790f`
- GitHub-recorded publication evidence time: `2026-10-05T04:38:26Z`
  (`2026-10-05T11:38:26+07:00`)
- Publication evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37264396502
- Workflow conclusion: `success`; the temporary tag-publishing workflow was
  removed after the tag target was verified.
- Pre-scan declaration: no new vulnerability-pair scan result had been produced
  or inspected after Amendment 02 and before the Amendment 03 adoption commit.
- Scope change: the primary command-injection family is CWE-77/CWE-78/CWE-88,
  while results remain separately reported by CWE. CWE-77 is eligible only when
  the vulnerable sink performs or initiates OS process/command execution under
  the frozen Linux/POSIX threat model; other CWE-77 interpreter cases are
  excluded from the primary scope with a recorded reason.

## 2026-10-05 — split-v0: deterministic language-stratified split

- Split artifact: `experiments/inventory/split_v0.json`
- Split generator: `experiments/make_split.py`
- Freeze commit: `72972469ea7b8da895ba4a3bdc2309676b04a953`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/72972469ea7b8da895ba4a3bdc2309676b04a953
- Tag: `split-v0`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/split-v0
- Verified tag target: `72972469ea7b8da895ba4a3bdc2309676b04a953`
- GitHub-recorded publication evidence time: `2026-10-05T06:59:16Z`
  (`2026-10-05T13:59:16+07:00`)
- Publication evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37275228419
- Split-generation evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37275106036
- Workflow conclusion: `success`.
- Unit of split: `group_id`; stratification is by language only.
- Hash rule: ascending SHA-256 of UTF-8 `group_id`; the first
  `ceil(40% * fresh eligible groups)` in each language are held out.
- JavaScript: 21 fresh eligible groups -> 9 held out and 12 development;
  with two previously exposed groups, total development is 14. Twelve groups
  are reserve and twelve are excluded.
- Python: 27 fresh eligible groups -> 11 held out and 16 development.
- Total held-out groups: 20.
- `cwe_unresolved` and non-primary CWE groups are reserve; pre-existing
  exclusions remain excluded. Explicit future `scope_verdict=out_of_scope`
  is excluded and `scope_verdict=unresolved` is reserve.
- No new Semgrep/CodeQL pair scan was run to create or inspect this split.

## 2026-10-05 — Amendment 04: pre-scan OS-command scope review

- Amendment: `experiments/amendments/AMENDMENT_04_SCOPE_REVIEW.md`
- Adoption commit: `f6243fa36784ecc88af2259bedc2b121a25f357d`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/f6243fa36784ecc88af2259bedc2b121a25f357d
- Tag: `amendment-04`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/amendment-04
- Verified tag target: `f6243fa36784ecc88af2259bedc2b121a25f357d`
- GitHub-recorded publication evidence time: `2026-10-05T08:25:58Z`
  (`2026-10-05T15:25:58+07:00`)
- Publication evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37283590108
- Workflow conclusion: `success`.
- Scope correction: the Linux/POSIX OS-process/command-execution sink condition
  now applies to CWE-77, CWE-78 and CWE-88.
- Scope review must use advisory/patch evidence without Semgrep/CodeQL output.
- Out-of-scope or unresolved held-out groups are not replaced, and split-v0 is
  not redrawn.
- No new vulnerable-pair Semgrep/CodeQL scan had been produced or inspected
  before adoption of this amendment.

## 2026-10-05 — Scope review v0 and split-v0.1

- Scope amendment: `experiments/amendments/AMENDMENT_04_SCOPE_REVIEW.md`
- Scope review commit: `246b46959c00e28bfc24dc3e2e62b265095bc995`
- Scope review artifact: `experiments/inventory/scope-review-v0.json`
- Human-readable scope report: `experiments/inventory/SCOPE_REVIEW_V0.md`
- Scope-evidence collection run:
  https://github.com/hungvietmai/security-triage/actions/runs/37284347406
- Scope review used advisory/fix-patch evidence only; no Semgrep/CodeQL pair
  output was used.
- Usable groups reviewed: **62**.
  - JavaScript: 34 in scope, 1 out of scope.
  - Python: 15 in scope, 12 out of scope.
- Mixed repository groups retained because they contain at least one in-scope
  pair row: `pyvul:mlflow/mlflow` and `pyvul:paddlepaddle/paddle`.
  Out-of-scope pair rows inside those groups are excluded from the primary
  denominator.

### split-v0.1 freeze

- Split artifact: `experiments/inventory/split_v0.1.json`
- Corrected split generator: `experiments/make_split.py`
- Freeze commit: `67f77a381ba2be64b9686f046715223bb508c46c`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/67f77a381ba2be64b9686f046715223bb508c46c
- Tag: `split-v0.1`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/split-v0.1
- Verified tag target: `67f77a381ba2be64b9686f046715223bb508c46c`
- GitHub-recorded publication evidence time: `2026-10-05T08:47:41Z`
  (`2026-10-05T15:47:41+07:00`)
- Tag publication evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37285860127
- Split verification/test run:
  https://github.com/hungvietmai/security-triage/actions/runs/37285579232
- The verification run confirmed that regenerated split-v0 is identical to the
  frozen split-v0 artifact before deriving v0.1.
- Test status: **31 experiment tests passed** (27 existing tests + 4 new split
  reproducibility/idempotence tests).
- `prior_exposure` is now an immutable input separate from generated `split`.
- `make_split.py --check` compares split-v0 without mutating the inventory.
- split-v0.1 is derived from frozen split-v0 by scope filtering only:
  `selection_redrawn=false`, `replacement_performed=false`.

Final effective group counts:

- JavaScript: 14 development, 9 held out, 11 reserve, 13 excluded.
- Python: 9 development, 6 held out, 12 excluded.
- Pooled held-out groups after scope review: **15**.
- Removed from frozen held-out without replacement:
  `pyvul:autogluon/autogluon`, `pyvul:pytorch/pytorch`,
  `pyvul:snowflakedb/snowflake-connector-python`,
  `pyvul:tankywoo/simiki`, and `pyvul:tensorflow/tensorflow`.
- Remaining held-out groups by in-scope CWE:
  - JavaScript: CWE-77 = 4, CWE-78 = 5.
  - Python: CWE-77 = 1, CWE-78 = 4, CWE-88 = 1.
- The pooled held-out total remains above the Amendment 02 minimum, but the
  Python held-out stratum is too small for a strong Python-specific
  effectiveness claim.
- No new vulnerable-pair Semgrep/CodeQL scan was run before this freeze.



## 2026-10-05 — Post-refactor real-scanner reproducibility check

- Verification candidate commit:
  `965ccc489be21842e5c7971db49ac09e99f55240`.
- GitHub Actions evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37297668652
- GitHub-recorded run time: `2026-10-05T10:36:34Z`
  (`2026-10-05T17:36:34+07:00`); workflow conclusion: `success`.
- The workflow checked out the candidate commit explicitly, built
  `experiments/Dockerfile`, and ran `curling@0.2.0` with the image's real
  Semgrep 1.178.0 and CodeQL 2.27.1 toolchains. Scanner functions were not
  replaced with test doubles.
- Smoke result: Semgrep = **0** raw findings, CodeQL = **6** raw findings,
  total = **6**, matching the recorded pre-refactor development result.
- `findings.json` was byte-identical to the pre-refactor Step 1 baseline.
- The generated `run.json` contained `runner_files_sha256` entries for all
  **9** runner files (the CLI plus eight `app/scanners` Python files).
- The same workflow verified the documented native commands with
  `PYTHONPATH` explicitly removed and passed the full **31-test** experiment
  suite using the CI command
  `PYTHONPATH=backend python -m unittest discover -s experiments -p 'test_*.py' -v`.
- This is a development reproducibility/integration check on the already exposed
  curling case. It is not a new held-out vulnerability-pair result and does not
  change the frozen split or evaluation claims.


## 2026-10-06 — Reconciliation v0 wired into the experiment CLI

- Verification branch head before this log entry:
  `4616e5f847e295f925873be9704b68e291b6111b`.
- GitHub Actions evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37425469495
- GitHub-recorded run start: `2026-10-06T06:44:40Z`
  (`2026-10-06T13:44:40+07:00`); conclusion: `success`.
- The verified Docker image ran the real pinned Semgrep and CodeQL toolchains on
  development case `curling@0.2.0`, then ran `sink-locator-v0` and
  `reconcile-v0`.
- Raw scanner preservation check: the generated `findings.json` was
  byte-identical to the Step 1 pre-refactor baseline.
- Raw result count remained **6**: Semgrep **0**, CodeQL **6**.
- Reconciliation output: `units.json` contained exactly **1** canonical unit:
  - `unit_id = 58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`
  - `sink_kind = child_process.exec`
  - `argument_role = shell_command`
  - all **6** CodeQL raw findings mapped to this unit.
- The run recorded **15** runner hashes: the CLI, eight `app/scanners/*.py`
  files, five `app/triage/*.py` files, and
  `experiments/locators/sink-locator-v0-javascript.yaml`.
- Verification quality gates in the same workflow:
  **122 backend tests passed**, backend coverage **90.36%**, and all
  **31 experiment tests passed**.
- No database write was introduced. `units.json` is a sidecar artifact and the
  raw finding ledger remains unchanged.
- This is a development integration/reproducibility check on an already exposed
  case. It does not add a held-out result or change the frozen split.


## 2026-10-06 — Day 3 reconciliation acceptance completed

- Acceptance PR: https://github.com/hungvietmai/security-triage/pull/1
- Verification workflow: https://github.com/hungvietmai/security-triage/actions/runs/37427597888
- Squash merge commit: `3929776ddf00136e890827023535a2e669b53bb8`.
- Reconciliation specification remained historically prior to implementation:
  `b295c5572cb3091682a637a37d1a161d93489c11` (specification) precedes
  `825229568d6cce3b2653d3ba936abe513b38769a` (locators) and
  `4b2e839f17eb7b40ea3dd731bbe1b597eea1ed61` (reconciler/CLI).
- The experiment CLI now enforces raw-finding conservation as a runtime
  postcondition: every raw finding ID must occur exactly once across reconciled
  units; loss or duplication fails the run.
- Experiment suite: **33 tests passed** (31 prior tests plus 2 conservation
  tests).
- Real pinned Docker scanner verification on `curling@0.2.0`:
  - baseline: **6 raw findings -> 1 canonical unit**;
  - baseline unit ID:
    `58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`;
  - baseline `findings.json` was byte-identical to the Step 1 baseline;
  - paired direct-alias control: Semgrep **1** + CodeQL **6** = **7 raw
    findings -> 1 canonical unit**;
  - paired unit used the same approved unit ID and recorded
    `tools = ["codeql", "semgrep"]`;
  - all 7 paired raw finding IDs were retained exactly once.
- Backend quality gates in the same CI workflow:
  - **122 backend tests passed**;
  - branch coverage **90.36%** (required floor 90%);
  - Ruff check and format check passed;
  - strict mypy passed with no issues in 80 source files;
  - Alembic `downgrade base` then `upgrade head` completed successfully,
    followed by a clean `alembic check`.
- Historical Semgrep-only direct-alias evidence/configuration was preserved;
  the paired integration control was added as a separate development config.
- No database write was introduced by reconciliation. No held-out case was
  opened or rescanned for this acceptance check.


## 2026-10-06 — reconcile-v0.1 corrective acceptance

- Specification amendment commit:
  `deb901594954930114c215d4e9792eefc7f39615`, committed before corrective code.
- Corrective implementation head verified by CI:
  `314adc5219acdacde8526434686964f5fea5292d`.
- GitHub Actions evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37435211454
- Reconciliation integration job conclusion: **success**.
- The pinned Docker image ran the real scanners on the already exposed
  `curling@0.2.0` development case after the reconcile-v0.1 role fixes.
- Baseline result remained **6 raw findings -> 1 canonical unit**; the paired
  direct-alias control remained **7 raw findings -> 1 canonical unit** with
  `tools = ["codeql", "semgrep"]`.
- `findings.json` remained byte-identical to the Step 1 baseline.
- The canonical curling unit ID did not change:
  `58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`.
- Raw-finding conservation remained satisfied for both configurations.
- Final substantive pre-merge head `40fa9ba1c433ed263671f4dd99bb2a96266daf7b` was re-verified by CI run #108 (`37438072270`): all four jobs succeeded; PostgreSQL migration verification completed `alembic check -> downgrade 0003 -> 0002 -> 0001 -> base -> upgrade head -> alembic check`, with **172 backend tests passed**, **92.93%** coverage, clean Ruff/mypy/dependency audit, and unchanged curling reconciliation acceptance.
- This corrective acceptance changes role resolution only where reconcile-v0
  was semantically wrong or over-confident. It does not redraw the frozen split,
  inspect a new held-out case, or change the canonical unit key.


## 2026-10-07 — preserved reconciliation commit-order evidence

PR #1 and PR #2 were squash-merged, so the intermediate specification and
implementation commits are not ancestors of `main`. To keep the cited research
history reachable independently of the merged PR branches, permanent evidence
refs were created at the exact historical commits:

- `evidence/reconcile-v0-spec` ->
  `b295c5572cb3091682a637a37d1a161d93489c11`
- `evidence/reconcile-v0-locators` ->
  `825229568d6cce3b2653d3ba936abe513b38769a`
- `evidence/reconcile-v0-implementation` ->
  `4b2e839f17eb7b40ea3dd731bbe1b597eea1ed61`
- `evidence/reconcile-v0.1-spec` ->
  `deb901594954930114c215d4e9792eefc7f39615`
- `evidence/reconcile-v0.1-implementation` ->
  `314adc5219acdacde8526434686964f5fea5292d`

Each evidence ref was compared with its target SHA and reported as identical
(0 commits ahead, 0 behind). These refs are intentionally separate from the
working PR branches and must not be deleted during ordinary branch cleanup.

For future research-significant specification, policy, or freeze changes, retain
the specification commit as a durable evidence ref before squash-merging, or
prefer a normal merge commit so the specification-before-implementation order
remains directly reachable from `main`.

## 2026-10-07 — Chính sách ưu tiên v0.1: đặc tả, triển khai và kiểm tra phát triển

- Đặc tả và bảng rule-claims v2 được commit tại
  `18d9109ab965dfceb9c22592d45203ffe310cee9`; tag từ xa
  `evidence/priority-v0.1-spec` đã được đối chiếu đúng SHA trước commit code
  `d4dba53058c88f65702bc7527441c56c19af46bf`. PR #4 giữ lịch sử bằng
  merge commit, không squash. Không dùng nhãn thủ công để tính mức ưu tiên.
- CLI bật vết Semgrep, giữ nguyên cảnh báo thô, xuất một assessment cho mỗi đơn vị,
  hash code, đặc tả, policy và bảng rule. Rule chỉ được phân loại khi định nghĩa
  đã đối chiếu hash từ file staged/query pack của chính lần chạy. Bộ gộp và
  `unit_id` vẫn theo `reconcile-v0.1`; không ghi database.
- Bốn cấu hình phát triển (SHA-256 file): curling smoke
  `adf762957905a891e62375d18a0241ee80487bfe0e29c2f5f98f4daced728ea8`,
  curling alias `850a036d32e91bb41d2a2163cbdc5e700fabe7e71a64e00f10fd0c286c7595ea`,
  R1 `d1662b74f833c9306d63586a273c45311efcaa95dd50af8de9aacc82168509d2`,
  OWASP Python `9650f7386ab685ea422c4b1920b10d490508152be2d876086fd8188f382d10ec`.
- CI #114 (`37567693424`) chạy scanner Docker thật: curling smoke 6 finding →
  1 đơn vị P1; cấu hình alias 7 finding → cùng đơn vị P1, có đồng thuận hai công
  cụ. `unit_id` vẫn là
  `58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`.
  ID, rule và vị trí chính của từng cảnh báo trùng baseline cũ; tính bảo toàn
  finding đạt. So byte giữa các lần chạy không còn là tiêu chí sau khi bật vết.
- R1 ở cùng run: 01 và 09 không tạo ứng viên; 04 có một đơn vị P4;
  03 có một đơn vị P1 và 05 một đơn vị P2. Các ca 02 và 08 không có ứng viên;
  06, 07 lần lượt P2; 10 P1. Không tạo đơn vị giả cho trường hợp scanner im lặng.
- OWASP Python cùng run: 31 finding → 18 đơn vị, **0 đơn vị U do toàn bộ rule
  chưa phân loại**. Trong các đơn vị gắn với nhãn đã rà soát: TP có P1=7,
  P2=4; FP có P1=2, P3=5. Hai FP vẫn lên P1 theo vết luồng và rule CodeQL
  `py/command-line-injection`; đây là giới hạn thực nghiệm cần phân tích, không
  được giải thích là đã giảm hết FP hoặc tự sửa chính sách v0.1 theo nhãn đã thấy.
  Nhãn OWASP đã được rà soát một vòng nhưng chưa có đánh giá độc lập thứ hai;
  kết quả này chỉ là chẩn đoán trên dữ liệu phát triển.
- CI #114 có job thực nghiệm, frontend và scanner integration xanh; backend
  Docker lỗi ở bước thu thập test vì image chỉ chứa `backend/`, còn test mới
  đọc file đặc tả ở `experiments/`. PR đã thêm mount chỉ đọc cho test và
  bổ sung kiểm tra cú pháp mảng literal JS; cần xác nhận lại trên HEAD cuối.
- HEAD code cuối trước log: `4f2ed0b81d3615380e3e1d04f1b64199212c49ff`.
  CI #115 (`37567998891`) **cả bốn job đều xanh**: 206 backend test qua,
  coverage nhánh 91,38% (ngưỡng 90%); 33 test thực nghiệm; Ruff, định dạng,
  mypy (87 file), rà soát phụ thuộc và frontend đạt. Trên PostgreSQL,
  `alembic check`, downgrade `0003 -> 0002 -> 0001 -> base`, upgrade về head
  và `alembic check` lần nữa đều đạt. Job Docker scanner lặp lại các số liệu
  curling, R1 và OWASP nêu trên, gồm bảo toàn ID/vị trí và cùng canonical
  `unit_id`. Run #114 chỉ là run trung gian, không dùng làm bằng chứng CI cuối.

## 2026-10-07 — Dọn code sau priority v0.1 (không đổi ngữ nghĩa chính sách)

- Chính sách vẫn là v0.1: không sửa `priority-v0.1.yaml`, `PRIORITY_V0_1.md` hay
  `rule-claims-v2.json`; chỉ đổi code, nên `runner_files_sha256` đổi theo.
- Luồng claims → evidence → policy, kiểm tra bảo toàn finding và dựng định nghĩa đã
  xác minh chuyển sang `backend/app/triage/assess.py` (hàm thuần, chỉ stdlib) để
  `run_pilot.py`, `probe_r1.py` và task worker ngày 5 dùng chung. Đọc source và chạy
  sink locator chuyển sang `app/scanners`. Parse YAML vẫn ở phía gọi.
- Hash policy và rule-claims nay tính trên đúng bytes đã parse, một lần mỗi run.
  Query CodeQL ngoài hai query đã khóa nay làm run thất bại thay vì bị gán nhầm
  `shell-command-constructed-from-input`.
- Assessment chỉ còn trường `priority` (YAML `output.required_fields`); bỏ bản sao
  `tier`. `probe_r1.py` nay cũng ghi hash policy/rule-claims vào assessment.
- Migration 0004: `unit_assessments` bỏ `semgrep_flag`, `codeql_flag`, `rule_claims`
  (đã có trong `evidence`), thêm `decision_id`, `matched_conditions`, `policy_id`,
  `policy_sha256`, `spec_sha256`, `rule_claims_version`, `rule_claims_sha256`.
- Kiểm chứng tương đương chạy local bằng image scanner Docker dựng từ `main`
  (`267764f`) và từ nhánh dọn code, cùng bốn bộ dữ liệu (curling smoke, curling alias,
  R1, OWASP Python): `findings.json`, `units.json` trùng hoàn toàn; `assessments.json`
  trùng hoàn toàn sau khi bỏ `tier` (R1: bỏ thêm các trường hash mới). Curling P1 ở cả
  hai cấu hình, R1 theo từng ca và phân bố OWASP (TP P1=7, P2=4; FP P1=2, P3=5) không
  đổi. Đây là kiểm tra local, chưa phải CI; cần ghi run CI trên commit cuối.
- `experiments/reports/owasp-python-development/reproduce.py` đã hỏng từ refactor
  `38e020d` (import `sarif_findings`, `verify_source_identity` từ `run_pilot` sau khi
  chúng chuyển sang `app.scanners`); nay import đúng chỗ và chạy lại được. Không đổi
  logic tái lập báo cáo.
- Key đường dẫn trong `runner_files_sha256`, `source_files` và hash query CodeQL nay
  luôn dùng `/` (`as_posix`); trên Linux kết quả không đổi, trên Windows trước đây
  sinh `\` làm hash query không khớp cấu hình.
- Chẩn đoán phát triển (một lần đo mỗi cấu hình, image local): `jobs=4` so với
  `jobs=1` giảm curling 61 s → 37 s, OWASP 179 s → 169 s (tạo CodeQL database cho
  Python không nhanh hơn). Với OWASP, `jobs=4` giữ nguyên tập finding, unit và mức
  ưu tiên nhưng **đổi thứ tự kết quả CodeQL nên `raw_id` dạng chỉ số bị gán khác**.
  Vì vậy cấu hình nghiên cứu giữ `jobs: 1` (gate `on_raw_id_reordering`), và bản ghi
  database không được dùng `raw_id` làm định danh ổn định giữa các lần quét.
