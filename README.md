# CyberSOC — A Multi-Agent AI Security Operations Center

CSAI 490/491 Senior Project · NewGiza University, School of Information Technology
Advisor: Dr. Hossam Hawash · Team: Nour Ayman Elkhouly, Maha Mikkawi, Merola Refaat

CyberSOC is a human-in-the-loop SOC assistant. Specialist agents analyze a security
alert from different angles, an orchestration agent merges their evidence into a single
case file, and a verification/critic agent rejects conclusions that are not backed by
evidence before anything reaches the analyst. Analysts keep authority over every
high-impact response action.

## Status (Milestone I)

| Component | Status |
|---|---|
| Dataset acquired (UNSW-NB15) + EDA | ✅ `src/cybersoc/detection/eda.py`, `reports/eda_summary.md` |
| Rule-based and Random Forest baselines | ✅ `src/cybersoc/detection/baseline.py`, `reports/baseline_results.json` |
| Shared agent message schema | ✅ `src/cybersoc/common/schema.py` |
| Critic agent, deterministic layer | ✅ `src/cybersoc/critic/rules.py` (+ tests) |
| Specialist agents, orchestrator, LLM critic, dashboard | ⏳ Milestone II onward |

### Baseline results (UNSW-NB15 official test split, 82,332 flows)

| Detector | Accuracy | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|
| Rule: `sttl >= 62` | 0.766 | 0.702 | 0.999 | 0.825 | **0.518** |
| Random Forest (200 trees) | 0.872 | 0.817 | 0.987 | 0.894 | **0.270** |

Multiclass Random Forest: accuracy 0.750, macro-F1 0.483 (Backdoor F1 0.06, Analysis F1 0.04).
These false-positive rates and rare-class failures are the gap the multi-agent pipeline
and critic agent target.

## Repository layout

```
configs/                 run configuration (LLM provider, thresholds)
data/raw/                UNSW-NB15 CSVs (not committed, see "Data")
data/processed/          derived features
docs/                    milestone reports, diagrams
notebooks/01_eda.ipynb   exploratory analysis walkthrough
reports/                 generated EDA summary, baseline metrics, figures
src/cybersoc/
  common/schema.py       Finding / Evidence / CaseFile shared by all agents
  agents/                specialist agents (network, anomaly, threat-intel, investigation)
  detection/             ML/DL detectors, EDA, baselines
  orchestrator/          LangGraph state graph that routes alerts between agents
  critic/                verification agent (rule layer now, LLM layer next)
tests/                   pytest suite
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # add your LLM API key (needed from Milestone II)
```

## Data

UNSW-NB15 (UNSW Canberra Cyber Range Lab), free for academic research.
Download `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` from
<https://research.unsw.edu.au/projects/unsw-nb15-dataset> into `data/raw/`.

Expected sizes: 175,341 training rows and 82,332 testing rows, 45 columns.

## Reproduce Milestone I results

```bash
export PYTHONPATH=src
python -m cybersoc.detection.eda --data-dir data/raw --out reports
python -m cybersoc.detection.baseline --data-dir data/raw --out reports
pytest -q
```

## Ethics and safety

All testing uses public datasets and an isolated lab (VMs/Docker). No agent executes
response actions on its own; recommended actions are surfaced to a human analyst.
