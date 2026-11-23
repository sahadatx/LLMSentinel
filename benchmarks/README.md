# Benchmark protocol

`dataset_v1.jsonl` contains 250 fixed synthetic samples in English and Bengali. Each row follows label schema `2.0` and includes:

- `id` and `category`
- `expected_disposition` (`allow` or `block`)
- `attack_family` and `technique`
- `language` and `source`
- `review_status` (`synthetic_unreviewed`, `human_reviewed`, or `ambiguous`)
- `split` (`train`, `validation`, or `holdout`)
- `label_version`

The positive class is a sample blocked by the filter. Dataset loading rejects missing or extra fields, unknown categories, duplicate IDs or prompts, labels inconsistent with the category, and unsupported split or review labels. All committed rows are marked `synthetic_unreviewed`. The partitions make deterministic regression comparisons possible; they are not human-reviewed holdout evidence or a production ground-truth set.

`make benchmark` measures the local input filter on the current machine. The timed section includes normalization, bounded decoding, entropy scoring, policy matching, and decision construction. Results include overall, split, category, and language confusion metrics; TPR/FPR Wilson confidence intervals; precision; benign-block rate; latency percentiles; environment; and dataset/policy SHA-256.

The benchmark excludes HTTP, JSON parsing, audit fsync, model/vector upstream latency, concurrency, and tool execution. Do not use it to claim a gateway SLA or real-world detection rate. Bengali rules are hand-authored lexical patterns and are represented only by synthetic unreviewed prompts. For release evidence, add a separately reviewed gold set, keep the holdout hidden from detector tuning, record reviewer provenance, and run a repeatable full-gateway load profile with fixed concurrency, request mix, payload sizes, warmup, and sample count.

`python -m benchmarks.load_gateway` (or `make load-benchmark`) measures a running local gateway with a bounded benign chat workload and reports client round-trip and gateway response percentiles separately. It checks posture first and refuses to send load to a configured provider unless `--allow-provider-upstream` is explicitly supplied. Remote HTTPS runs require `--allow-remote-target`. Use a test tenant and a policy rate limit sized for the chosen request count; rate-limited requests are reported separately and excluded from successful-response percentiles. Save the JSON output with the policy/dataset revision, deployment image, concurrency, payload mix, and acceptance criteria when collecting release evidence.
