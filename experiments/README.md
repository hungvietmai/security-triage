# Thực nghiệm

Trạng thái, kết quả và việc còn mở: [docs/research.md](../docs/research.md).
File này gồm bản đồ thư mục, cách chạy và quy ước khóa. Quy tắc viết test:
[AGENTS.md](AGENTS.md).

Ký hiệu 🔒 đánh dấu tài liệu bị khóa bằng SHA-256: không sửa, không đổi tên (xem
[Tài liệu bị khóa](#tài-liệu-bị-khóa)).

## Bản đồ thư mục

### Nghiên cứu hiện tại: CWE-22, bằng chứng an toàn CodeQL (từ 15/10)

| Thư mục | Nội dung | Tài liệu chính |
|---|---|---|
| [owasp-bp-pilot/](owasp-bp-pilot/) | Thí điểm BenchmarkPython 4 CWE (Semgrep, CodeQL, Bandit). QL v0.1 ở `ql/`, QL v0.2 ở `ql_v02/` (baseline cho mọi bước sau). Bộ 47 phản ví dụ | [README](owasp-bp-pilot/README.md), [FREEZE_DEVIATION](owasp-bp-pilot/FREEZE_DEVIATION.md) 🔒 |
| [wave-a/](wave-a/) | v0.2 trên Flask-Admin và Paperless-ngx | [README](wave-a/README.md) 🔒 |
| [wave-b/](wave-b/) | 11 cặp CVE lỗi/vá: chọn mẫu, kết quả, nhãn 60 cảnh báo, query rà soát | [SELECTION_PROTOCOL](wave-b/SELECTION_PROTOCOL.md) 🔒, [RESULTS](wave-b/results/RESULTS.md) |
| [v03-interprocedural-guard/](v03-interprocedural-guard/) | Đặc tả và QL v0.3 strict/scoped, phản ví dụ, bảng kỳ vọng, khóa dual | [README](v03-interprocedural-guard/README.md) 🔒, [SPEC](v03-interprocedural-guard/SPEC.md) 🔒, [DECISION](v03-interprocedural-guard/DECISION_2026-10-20.md) 🔒 |
| [wave-c/](wave-c/) | Đánh giá độc lập: giao thức, chọn mẫu, runner, evaluator, kết quả, hồ sơ đóng đợt | [PROTOCOL](wave-c/PROTOCOL.md) 🔒, [DECISION](wave-c/DECISION_2026-10-21.md), [closeout/STATUS](wave-c/closeout/STATUS.md) |
| [v021-normalization/](v021-normalization/) | Bản thử v0.2.1 (chỉ dùng cho phát triển) | [README](v021-normalization/README.md), [DECISION](v021-normalization/DECISION_2026-10-21.md) |
| [reviews/2026-10-27-assistant-pass1/](reviews/2026-10-27-assistant-pass1/) | Assistant rà kỹ thuật 8 sink C và 17 cảnh báo B; nhãn đề xuất và evaluator, không thay human review | [README](reviews/2026-10-27-assistant-pass1/README.md) |
| [reviews/owner-verification/](reviews/owner-verification/) | Chủ đề án xác minh các nhãn đề xuất (28–29/10); nhãn đợt C và B, kết quả evaluator | [README](reviews/owner-verification/README.md) |

Gói kết quả của đợt C:

- `results/study-001/`: kết quả scanner, hàng đợi rà và template nhãn.
- `results/review-001/`: hậu kiểm source và bản nháp diễn giải.
- `results/paths-001/`: 18 đường đi CodeQL mẫu cho 8 sink.
- `closeout/`: báo cáo tổng hợp, khảo sát hợp đồng, tự rà kỹ thuật và hồ sơ owner review.

Các gói `results/*` đều bị khóa.

### Giai đoạn CWE-78 (24/09–08/10, lịch sử)

Giai đoạn này đã dừng, nhưng mã của nó vẫn được ứng dụng (profile `command-injection-v0.1`)
và CI (`experiments`, `scan-parity`) sử dụng.

| Thư mục / tệp | Nội dung |
|---|---|
| [EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md), [amendments/](amendments/) | Giao thức v1.0.0 và Amendment 01–05. `run_pilot.py` ghi hash của giao thức vào `run.json`, nên đừng sửa file này |
| [RESEARCH_LOG.md](RESEARCH_LOG.md) 🔒 | Nhật ký 24/09–08/10 |
| `run_pilot.py`, `run_batch.py` | CLI quét theo manifest (npm; GitHub JS/Python): Semgrep và CodeQL, giữ SARIF thô, gộp đơn vị, chạy priority v0.1 |
| `cases/`, `configs/`, `rules/`, `batches/` | Manifest ca, cấu hình scanner, rule Semgrep (`rules/batch-01/` và `rules/python-upstream/` thuộc profile), danh sách đợt |
| `locators/`, `mappings/`, `policy/` | Định vị sink JS bằng Babel, rule-claims v1/v2, priority v0 và v0.1 ([PRIORITY_V0_1.md](policy/PRIORITY_V0_1.md) 🔒, được profile của ứng dụng ghim) |
| [RECONCILIATION_V0.md](RECONCILIATION_V0.md), [REVIEW_WORKFLOW.md](REVIEW_WORKFLOW.md), `build_review.py`, `annotate_claims.py` | Đặc tả bộ gộp và quy trình rà |
| `build_profile.py` | Sinh `profiles/command-injection-v0.1/` |
| [reports/](reports/), `fixtures/`, `diagnostics/`, `labels/`, `taxonomy/` | Báo cáo từng đợt phát triển, fixture tổng hợp, script chẩn đoán, nhãn OWASP CWE-78, phân loại nguyên nhân gốc |
| [inventory/](inventory/), [pairs/](pairs/), `schemas/`, `make_split*.py`, `make_pair_manifests.py`, `lock_pair_sources.py`, `patch_hunks.py`, `known_locations.py`, `fetch_cwe.py`, `audit_pair_inventory.py` | Kho cặp lỗi/vá, split, manifest, khóa nguồn, vị trí lỗi (pairs-v1; chưa quét) |
| `Dockerfile` | Image thực nghiệm (Semgrep và CodeQL đã ghim) |

`tests/` chứa toàn bộ test của cả hai giai đoạn (85 test tại commit `8e99ecc`).

## Cách chạy

Mọi lệnh chạy từ thư mục gốc của repository. Phiên bản công cụ được ghim ở
[tools/pins.env](../tools/pins.env).

### Test

```powershell
npm --prefix experiments/locators ci --ignore-scripts
uv run --project backend --with-requirements experiments/requirements-pairs.txt python -m unittest discover -s experiments/tests -p 'test_*.py' -v
```

Các script bị khóa (v0.3, owasp-bp-pilot, wave-c, `known_locations.py`, `patch_hunks.py`…) vẫn
đọc/ghi bằng bảng mã mặc định và không được sửa. Trên Windows, đặt `$env:PYTHONUTF8 = "1"`
trước khi chạy chúng.

### Kiểm tra khóa

```powershell
python experiments/wave-c/select_repositories.py --check
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --metadata experiments/v03-interprocedural-guard/FREEZE_v0.3_dual.json
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --manifest experiments/wave-c/LOCK.sha256
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --manifest experiments/wave-c/EXECUTION_LOCK.sha256
```

Lệnh `--metadata` cần archive trong `artifacts/v03/`. Thư mục này bị Git bỏ qua, nên lệnh chỉ
chạy được trên máy có archive. Workflow `research-publication.yml` chạy lệnh cuối cùng mỗi khi
`EXECUTION_LOCK.sha256` thay đổi.

### Đợt C: chấm nhãn bằng evaluator đã khóa

Evaluator chỉ đọc kết quả đã lưu, không quét lại. Mỗi lần chạy cần một thư mục output mới:

```powershell
python experiments/wave-c/evaluate.py --run experiments/wave-c/results/study-001/evaluation_run.json --labels experiments/wave-c/closeout/owner-review/labels.owner-pass1.json --output artifacts/wave-c/owner-review-pass1-001
```

Mã thoát 2 có thể có nghĩa là `failed_acceptance`. Khi đó giữ nguyên báo cáo, không sửa nhãn.
Quy trình rà: [START_HERE.md](wave-c/closeout/owner-review/START_HERE.md).
Cách chạy lại scanner: [EXECUTION_GUIDE.md](wave-c/EXECUTION_GUIDE.md) 🔒.
Bản thử v0.2.1: [v021-normalization/README.md](v021-normalization/README.md) (chạy qua WSL).

### CLI giai đoạn CWE-78

Chạy qua Docker (Linux x86-64). Thư mục output phải là thư mục mới:

```bash
docker build -f experiments/Dockerfile -t security-triage-pilot .
docker run --rm -v "$(pwd)/artifacts:/app/artifacts" security-triage-pilot \
  --case experiments/cases/secbench-curling-0.2.0.json \
  --config experiments/configs/development-smoke-javascript.json \
  --configuration-commit 8ffd191a4b63d74db3b655aeb08c3ce9aa33a4c5 \
  --output artifacts/curling-local-001
```

Chạy native cần Python 3.12+, Semgrep 1.178.0, CodeQL 2.27.1 và query pack đúng ngôn ngữ:
truyền `--semgrep`, `--codeql` và `--javascript-query-pack` hoặc `--python-query-pack`.
CLI chỉ nhận ca thuộc tập phát triển.

Output gồm archive và source đã giải nén, case/config đã ghim, log phiên bản/tiến trình, SARIF,
`findings.json`/`.csv`, `units.json`, `assessments.json`, `run.json` và CodeQL database.
`artifacts/` bị Git bỏ qua.

### Profile quét của ứng dụng

`profiles/command-injection-v0.1/profile.json` trỏ tới config, rule, locator, rule-claims và
policy trong thư mục này, kèm SHA-256 của từng file. File sinh ra duy nhất là `priority-v0.1.json`.

Sau khi đổi một file đã được ghim, chạy `python experiments/build_profile.py` rồi commit kết
quả; CI (`test_profile.py`) sẽ fail nếu profile lỗi thời. Worker từ chối khởi động nếu hash
hoặc phiên bản scanner lệch.

## Tài liệu bị khóa

Một file bị coi là khóa khi SHA-256 hiện tại của nó xuất hiện trong một manifest:

- `*.sha256`: `FREEZE_*`, `LOCK`, `EXECUTION_LOCK`, `LABELS_LOCK`, `RESULTS_LOCK`,
  `PATHS_LOCK`, `REVIEW_LOCK`, `SELF_REVIEW_LOCK`, `INPUTS_LOCK`, `EXPECTATIONS`;
- `FREEZE_v0.3_dual.json`;
- `profiles/command-injection-v0.1/profile.json`.

Sửa một file như vậy sẽ phá kiểm tra khóa, hoặc khiến worker từ chối khởi động. Kiểm tra trước khi sửa:

```bash
git grep -l "$(sha256sum <file> | cut -c1-64)"
```

Có kết quả nghĩa là file bị khóa. Khi đó, ghi trạng thái mới vào
[docs/research.md](../docs/research.md) hoặc một tài liệu mới trong đúng thư mục giai đoạn.

Tài liệu Markdown đang bị khóa (ngày 2026-10-27):

- `../SECURITY_TRIAGE_AGENT_HANDOFF_2026-10-20.md`, `RESEARCH_LOG.md`,
  `policy/PRIORITY_V0_1.md`, `owasp-bp-pilot/FREEZE_DEVIATION.md`
- `v03-interprocedural-guard/`: `README.md`, `SPEC.md`, `SPEC_RESOURCE.md`, `DECISION_2026-10-20.md`
- `v021-normalization/`: `PLAN.md`, `results/round-001/RESULTS.md`
- `wave-a/README.md`, `wave-b/SELECTION_PROTOCOL.md`
- `wave-c/`: `README.md`, `PROTOCOL.md`, `EXECUTION_GUIDE.md`, `EXECUTION_LOG.md`,
  `closeout/self-review/REVIEW.md`, và mọi tệp `.md` trong `results/study-001/`,
  `results/review-001/`, `results/paths-001/`

Các báo cáo có ngày khác (thư mục `reports/`, `batches/`, `amendments/`, `inventory/`…) là
hồ sơ lịch sử: không bị khóa, nhưng cũng không viết lại nội dung.
