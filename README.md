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
| Dataset acquired (UNSW-NB15) + EDA | ✅ `notebooks/01_eda.ipynb`, `reports/eda_summary.md` |
| Project repository and setup files | ✅ |
| Detection models, agents, critic, dashboard | ⏳ Next milestones |

## Repository layout

```
data/raw/                UNSW-NB15 CSVs (not committed, see "Data")
data/processed/          derived features
notebooks/01_eda.ipynb   exploratory analysis walkthrough
reports/                 EDA summary and figures
src/cybersoc/detection/  EDA helper code used by the notebook
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

## Reproduce the EDA

```bash
export PYTHONPATH=src
python -m cybersoc.detection.eda --data-dir data/raw --out reports
```

Or open `notebooks/01_eda.ipynb` in Jupyter.

## Ethics and safety

All testing uses public datasets and an isolated lab (VMs/Docker). No agent executes
response actions on its own; recommended actions are surfaced to a human analyst.
