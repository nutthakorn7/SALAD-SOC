# SALAD: SOC Alert Labeled Analysis Dataset

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18912306.svg)](https://doi.org/10.5281/zenodo.18912306)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![HuggingFace](https://img.shields.io/badge/🤗_HuggingFace-SALAD--SOC-yellow)](https://huggingface.co/datasets/nutthakorn7/SALAD-SOC)

**SALAD** is a unified benchmark dataset containing **2,778,424 SOC alerts** derived from [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset). Each alert is enriched with MITRE ATT&CK mapping, triage decisions, priority scores, and natural language descriptions.

## 📊 Dataset Statistics

| Split | Records | Size |
|-------|---------|------|
| Train | 2,222,739 | 615 MB |
| Validation | 277,843 | 132 MB |
| Test | 277,842 | 132 MB |
| **Total** | **2,778,424** | **921 MB** |

## 🎯 Benchmark Tasks

| # | Task | Type | Classes |
|---|------|------|---------|
| 1 | Binary Classification | Binary | Benign vs Malicious |
| 2 | Alert Triage | 3-class | Escalate / Investigate / Suppress |
| 3 | Priority Scoring | Regression | 0.0 – 1.0 |
| 4 | Attack Categorization | Multi-class | 15 attack categories |

## 🔑 Key Features

- **29-field unified schema** across all alerts
- **MITRE ATT&CK** tactic and technique mapping
- **Cyber Kill Chain** phase labels
- **Severity scoring** (Low/Medium/High/Critical)
- **Triage decisions** (Escalate/Investigate/Suppress)
- **Difficulty levels** (Easy/Medium/Hard)
- **Natural language descriptions** for LLM evaluation

## 🚀 Quick Start

```python
import pandas as pd

# Load data
train = pd.read_csv("salad_train.csv")
test = pd.read_csv("salad_test.csv")

# Run baselines
python evaluate.py --task all --max-train 50000
```

## 📈 Baseline Results

| Task | Metric | Logistic Regression | Random Forest |
|------|--------|-------------------|---------------|
| Classification | F1 | 0.857 | 0.958 |
| Triage | F1 | 0.616 | 0.975 |
| Prioritization | MAE | 0.098 | 0.039 |
| Attack Category | F1 | 0.390 | 0.548 |

## 📂 File Structure

```
├── salad_train.csv    # Training set (2.2M alerts)
├── salad_test.csv     # Test set (278K alerts)
├── salad_val.csv      # Validation set (278K alerts)
├── stats.json         # Dataset statistics
├── datacard.md        # Detailed data card
├── evaluate.py        # Evaluation & baseline scripts
└── LICENSE            # CC-BY 4.0
```

## 📄 Citation

```bibtex
@dataset{chalaemwongwan_2026_salad,
  author       = {Chalaemwongwan, Nutthakorn},
  title        = {SALAD: SOC Alert Labeled Analysis Dataset},
  year         = 2026,
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.18912306},
  url          = {https://doi.org/10.5281/zenodo.18912306}
}
```

## 📜 License

This dataset is licensed under [Creative Commons Attribution 4.0 International (CC-BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

## 🔗 Links

- 📦 [Zenodo (DOI)](https://doi.org/10.5281/zenodo.18912306)
- 🤗 [HuggingFace](https://huggingface.co/datasets/nutthakorn7/SALAD-SOC)
- 📧 Contact: nutthakorn.ch@kmitl.ac.th
