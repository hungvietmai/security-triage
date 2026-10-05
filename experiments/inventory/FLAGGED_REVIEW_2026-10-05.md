# Flagged inventory review — 2026-10-05

This review was performed before any new Semgrep/CodeQL pair scan.

## Summary

- SecBench.js rows checked against npm: **47**
- `fix_commit` repository mismatches vs GHSA `source_code_location`: **1**
- vulnerable/fixed version equality flags: **2**
- missing vulnerable npm versions after normalization: **0**
- missing fixed npm versions before repair/exclusion: **4**
- SecBench.js rows excluded after review: **12**
- PyVul fixing commits queried through GitHub API: **36**
- PyVul rows with no parent: **0**

## SecBench.js flagged rows

| pair_id | flags | action | GHSA source | fixed version after | status |
|---|---|---|---|---|---|
| secbench-alfred-workflow-nodejs-2.0.1 | ghsa_package_mismatch, fixed_equals_vulnerable | excluded_ghsa_package_mismatch, excluded_unresolved_same_version | — | 2.0.1 | excluded |
| secbench-command-exists-1.2.2 | ghsa_package_mismatch, fixed_version_missing_npm | excluded_ghsa_package_mismatch, excluded_missing_fixed_version | — | 0.22.2 | excluded |
| secbench-diskstats-0.0.2 | ghsa_package_mismatch, fixed_version_missing_npm | excluded_ghsa_package_mismatch, excluded_missing_fixed_version | — | 2.0.1 | excluded |
| secbench-gm-1.20.0 | fixed_equals_vulnerable | repaired_fixed_version_from_ghsa:1.21.1 | https://github.com/aheckmann/gm | 1.21.1 | unassigned |
| secbench-pdf-image-1.0.5 | fixed_version_missing_npm | repaired_missing_fixed_version_from_ghsa:2.0.0 | https://github.com/roest01/node-pdf-image | 2.0.0 | unassigned |
| secbench-samsung-remote-1.2.5 | ghsa_package_mismatch | excluded_ghsa_package_mismatch | https://github.com/ronomon/opened | 1.5.2 | excluded |
| secbench-scp-0.0.3 | ghsa_package_mismatch, fixed_version_missing_npm | excluded_ghsa_package_mismatch, excluded_missing_fixed_version | — | 0.22.2 | excluded |
| secbench-find-process-1.4.4 | ghsa_package_mismatch, fixed_version_absent | excluded_ghsa_package_mismatch | — | — | excluded |
| secbench-im-metadata-3.0.1 | fixed_version_absent | no change | — | — | excluded |
| secbench-im-resize-2.3.2 | fixed_version_absent | no change | — | — | excluded |
| secbench-macfromip-1.1.1 | fixed_version_absent | no change | — | — | excluded |
| secbench-strider-git-1.0.3 | ghsa_package_mismatch, fixed_version_absent | excluded_ghsa_package_mismatch | — | — | excluded |
| secbench-vboxmanage.js-1.0.6 | ghsa_package_mismatch, fixed_version_absent | excluded_ghsa_package_mismatch | — | — | excluded |
| secbench-xps-1.0.2 | fix_commit_repo_mismatch, ghsa_package_mismatch, fixed_version_absent | excluded_ghsa_package_mismatch | https://github.com/adriano-di-giovanni/node-df | — | excluded |

## Action counts

- `excluded_ghsa_package_mismatch`: 9
- `excluded_missing_fixed_version`: 3
- `excluded_unresolved_same_version`: 1
- `repaired_fixed_version_from_ghsa:1.21.1`: 1
- `repaired_missing_fixed_version_from_ghsa:2.0.0`: 1

## PyVul parent verification

| pair_id | fix commit | first parent | parent count | action |
|---|---|---|---:|---|
| pyvul-django-django-e1e81aa1c442 | `e1e81aa1c4427411e3c68facdd761229ffea6f6f` | `a708f39ce67af174df90c5b5e50ad1976cec7cb8` | 1 | confirmed_parent |
| pyvul-jaspernbrouwer-powerline-gitstatus-fe8e963b3489 | `fe8e963b3489e4cceaa2c1f26f2bcc2ef405364c` | `8000c7f41305ddb421528dd00b6292ffd121c2c2` | 1 | confirmed_parent |
| pyvul-tensorflow-tensorflow-8b202f08d52e | `8b202f08d52e8206af2bdb2112a62fafbc546ec7` | `349172cf0ac29ba1346d244a40dc4761b4600f2e` | 1 | confirmed_parent |
| pyvul-google-slo-generator-36318beab1b8 | `36318beab1b85d14bb860e45bea186b184690d5d` | `50ce1bf81d7c6a97da52cf167b1d3ee8100ddd90` | 1 | confirmed_parent |
| pyvul-jupyterhub-binderhub-195caac17269 | `195caac172690456dcdc8cc7a6ca50e05abf8182` | `034430adc8ed379135f3ef46ee6ca650781ef67c` | 1 | confirmed_parent |
| pyvul-PaddlePaddle-Paddle-c5f6862d118d | `c5f6862d118d7d69210f0e73bea1b055f5f21f2b` | `e64a054ff6b3964070fb2eb24c9aace2db5965eb` | 1 | confirmed_parent |
| pyvul-PaddlePaddle-Paddle-49bec1760535 | `49bec176053595975c1941cff9749c55f7203ea9` | `5252c5d358807edcb5b61b06e4853b894478c0bf` | 1 | confirmed_parent |
| pyvul-PaddlePaddle-Paddle-5ed9478fdef9 | `5ed9478fdef96a06eeec9093f9e768c97b094af3` | `372062dfa0b2f1ba293b497a6c24c46f60b61214` | 1 | confirmed_parent |
| pyvul-yt-dlp-yt-dlp-de015e930747 | `de015e930747165dbb8fcd360f8775fd973b7d6e` | `61bdf15fc7400601c3da1aa7a43917310a5bf391` | 1 | confirmed_parent |
| pyvul-mlflow-mlflow-6dde93758d42 | `6dde93758d42455cb90ef324407919ed67668b9b` | `330bf0b38b07d4adf3fae99af1b44c8e857f514a` | 1 | confirmed_parent |
| pyvul-langchain-ai-langchain-a2f191a32229 | `a2f191a32229256dd41deadf97786fe41ce04cbb` | `61938a02a1e76fa6c6e8203c98a9344a179c810d` | 1 | confirmed_parent |
| pyvul-dwisiswant0-apkleaks-a966e781499f | `a966e781499ff6fd4eea66876d7532301b13a382` | `8577b7af6224bf0a5455b552963c46721308d2ff` | 1 | confirmed_parent |
| pyvul-celery-celery-1f7ad7e6df1e | `1f7ad7e6df1e02039b6ab9eec617d283598cad6b` | `2d8dbc2a8087bbb60590465031ebd5138b8eb359` | 1 | confirmed_parent |
| pyvul-mlflow-mlflow-a98a341a7222 | `a98a341a7222f894b7735db575ad9311ecaba4e3` | `64b4645b0a0c0f6713b17f127403f267019efbfe` | 1 | confirmed_parent |
| pyvul-pypa-pip-389cb799d0da | `389cb799d0da9a840749fcd14878928467ed49b4` | `71df02c412998aa07c358ad04388e1573b3c5348` | 1 | confirmed_parent |
| pyvul-dgilland-pydash-6ff0831ad285 | `6ff0831ad285fff937cafd2a853f20cc9ae92021` | `1947d2ad210129d1c2925f0c8837323d7fd420db` | 1 | confirmed_parent |
| pyvul-nexB-scancode.io-07ec0de1964b | `07ec0de1964b14bf085a1c9a27ece2b61ab6105c` | `2f5a6cce23058684633326fc27b0f052a218b64e` | 1 | updated_parent |
| pyvul-snowflakedb-snowflake-connector-python-1cdbd3b1403c | `1cdbd3b1403c5ef520d7f4d9614fe35165e101ac` | `4b1d4741eb6e902dd415ad7cd91fc04c231bcca4` | 1 | confirmed_parent |
| pyvul-pytorch-pytorch-767f6aa49fe2 | `767f6aa49fe20a2766b9843d01e3b7f7793df6a3` | `fbbf3687453aed1b732eee6f6e9050258ce29561` | 1 | confirmed_parent |
| pyvul-WeblateOrg-weblate-35d59f1f0405 | `35d59f1f040541c358cece0a8d4a63183ca919b8` | `d83672a3e7415da1490334e2c9431e5da1966842` | 1 | confirmed_parent |
| pyvul-WeblateOrg-weblate-d83672a3e741 | `d83672a3e7415da1490334e2c9431e5da1966842` | `9a5a09781e5a19ab9a24878afb08c9fcafb21ca7` | 1 | confirmed_parent |
| pyvul-tankywoo-simiki-45da0ab7c1e9 | `45da0ab7c1e94b368cac22867e7ac9a42dbb9390` | `085bb77ca3b493eb28c9ea0930e2e39c5a7bb72d` | 1 | confirmed_parent |
| pyvul-ansible-ansible-35938b907dfc | `35938b907dfcd1106ca40b794f0db446bdb8cf09` | `bab1ac1d5c175555ca5ddd3b1dd30ad04e47f7b1` | 1 | confirmed_parent |
| pyvul-apache-airflow-2844dad1c762 | `2844dad1c762f5c7dd1271866d3661bf66657300` | `8dc895cbb64e991893705b04e03a6655c35888fe` | 1 | confirmed_parent |
| pyvul-savon-noir-python-libnmap-c36fecde9001 | `c36fecde90017befeb4853396d0e2aac93c95b64` | `28060b437e800d9bc9840cca8f171ce7a3fb34dd` | 1 | confirmed_parent |
| pyvul-ray-project-ray-193ff8c80067 | `193ff8c80067aed4037755cc10f15eb6986dfe95` | `79a5643238f890f0b163c3a886aa51d1abc6e4f7` | 1 | confirmed_parent |
| pyvul-huggingface-transformers-2272ab57a99b | `2272ab57a99bcac972b5252b87c31e24d0b25538` | `87a6cf41d0faa2df5bd464273534e928c6ac6e99` | 1 | confirmed_parent |
| pyvul-abilian-abilian-devtools-9d71b0d3b6b4 | `9d71b0d3b6b467589d58aacc932ca3dc7e524ce2` | `ea3a13a532dee1760bfea21bd50bed5467a5c25c` | 1 | confirmed_parent |
| pyvul-cyanomiko-dcnnt-py-b4021d784a97 | `b4021d784a97e25151a5353aa763a741e9a148f5` | `4084ea18f96d9a953315f5555fca45f26639b8be` | 1 | confirmed_parent |
| pyvul-mlflow-mlflow-802911381717 | `8029113817175cc9b9bed5c1bebe2f9afea2835b` | `81deca5725b31a931d85f9dfa7eec0e65750bbb9` | 1 | confirmed_parent |
| pyvul-ansible-ansible-03aff644cc1c | `03aff644cc1c00e1f7551195c68fbd0d13a39e6e` | `578fa17af58ae665cc652c530f1de6562659665c` | 1 | confirmed_parent |
| pyvul-ansible-ansible-4c8c40fd3d4a | `4c8c40fd3d4a58defdc80e7d22aa8d26b731353e` | `473df5c13f8fe1b2b7efb4a65b0a0b3887e85b39` | 1 | confirmed_parent |
| pyvul-ansible-ansible-8aa850e3573e | `8aa850e3573e48c9a2f12aef84e8a3a6f5ba4847` | `67d2d139975eed0b0c38ce3e0255d5ad06716d47` | 1 | confirmed_parent |
| pyvul-ansible-ansible-8b17e5b9229f | `8b17e5b9229ffaecfe10a4881bc3f87dd2c184e1` | `c49092fd2929e85276bfe60fc63d3f47f8aa4646` | 1 | confirmed_parent |
| pyvul-pgadmin-org-pgadmin4-35f05e49b363 | `35f05e49b3632a0a674b9b36535a7fe2d93dd0c2` | `61fa8b16c90590b59c624e440187441349020e1a` | 1 | confirmed_parent |
| pyvul-autogluon-autogluon-23a37e74e58d | `23a37e74e58d03055c84a1b89c5af6c3db296b5e` | `1a62b445e4fd797fcb5e3fac26d532fecfec74c6` | 1 | confirmed_parent |

## Audit rules

- GHSA package identity is checked before using `first_patched_version`.
- A mismatched SecBench.js `fix_commit` is removed when the GHSA package matches; the GHSA source repository is retained in provenance.
- If the GHSA package itself does not match the npm package, the row is excluded rather than repaired by inference.
- npm versions are checked against the registry metadata for the exact package.
- PyVul vulnerable snapshots use the first parent returned by one GitHub commit API request per fixing commit.
- No scanner result was used by this review.
