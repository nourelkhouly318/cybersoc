# UNSW-NB15 — initial EDA summary

| | Train | Test |
|---|---|---|
| Records | 175,341 | 82,332 |
| Columns | 45 | 45 |
| Numeric / categorical features | 39 / 3 | 39 / 3 |
| Normal / attack | 56,000 / 119,341 | 37,000 / 45,332 |
| Missing cells | 0 | 0 |
| Duplicate rows (excl. id) | 67,601 | 26,387 |
| `service` = '-' (unknown) | 53.7% | 57.3% |

## Records per attack category (train)

| Category | Records | Share |
|---|---|---|
| Normal | 56,000 | 31.94% |
| Generic | 40,000 | 22.81% |
| Exploits | 33,393 | 19.04% |
| Fuzzers | 18,184 | 10.37% |
| DoS | 12,264 | 6.99% |
| Reconnaissance | 10,491 | 5.98% |
| Analysis | 2,000 | 1.14% |
| Backdoor | 1,746 | 1.00% |
| Shellcode | 1,133 | 0.65% |
| Worms | 130 | 0.07% |

## Top features by |correlation| with label

- `sttl`: 0.693
- `ct_state_ttl`: 0.578
- `dload`: 0.394
- `ct_dst_sport_ltm`: 0.357
- `dmean`: 0.342
- `rate`: 0.338
- `swin`: 0.334
- `dwin`: 0.32
- `ct_src_dport_ltm`: 0.306
- `ct_dst_src_ltm`: 0.304

Highly redundant pairs (|r| > 0.95): 12
- `spkts` ~ `sbytes` (0.964)
- `spkts` ~ `sloss` (0.971)
- `dpkts` ~ `dbytes` (0.972)
- `dpkts` ~ `dloss` (0.979)
- `sbytes` ~ `sloss` (0.996)
- `dbytes` ~ `dloss` (0.997)
- `swin` ~ `dwin` (0.99)
- `ct_srv_src` ~ `ct_dst_src_ltm` (0.967)
- `ct_srv_src` ~ `ct_srv_dst` (0.98)
- `ct_dst_ltm` ~ `ct_src_dport_ltm` (0.962)
- `ct_dst_src_ltm` ~ `ct_srv_dst` (0.972)
- `is_ftp_login` ~ `ct_ftp_cmd` (1.0)

Categories present only in test: {'proto': [], 'service': [], 'state': ['ACC', 'CLO']}
