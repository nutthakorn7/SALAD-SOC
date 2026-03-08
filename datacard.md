---
language:
- en
license: cc-by-4.0
size_categories:
- 1M<n<10M
task_categories:
- tabular-classification
- tabular-regression
tags:
- cybersecurity
- soc
- alert-triage
- mitre-attack
- intrusion-detection
- network-security
- kill-chain
pretty_name: SALAD - SOC Alert Labeled Analysis Dataset
dataset_info:
  features:
    - name: alert_id
      dtype: string
    - name: timestamp
      dtype: string
    - name: source_dataset
      dtype: string
    - name: src_ip
      dtype: string
    - name: dst_ip
      dtype: string
    - name: src_port
      dtype: int64
    - name: dst_port
      dtype: int64
    - name: protocol
      dtype: string
    - name: flow_duration
      dtype: float64
    - name: total_fwd_packets
      dtype: int64
    - name: total_bwd_packets
      dtype: int64
    - name: flow_bytes_per_sec
      dtype: float64
    - name: alert_type
      dtype: string
    - name: severity
      dtype: string
    - name: confidence
      dtype: float64
    - name: mitre_tactic
      dtype: string
    - name: mitre_technique
      dtype: string
    - name: kill_chain_phase
      dtype: string
    - name: network_segment
      dtype: string
    - name: is_malicious
      dtype: bool
    - name: attack_category
      dtype: string
    - name: triage_decision
      dtype: string
    - name: priority_score
      dtype: float64
    - name: difficulty_level
      dtype: string
    - name: alert_description
      dtype: string
    - name: alert_count_1h
      dtype: int64
    - name: alert_count_24h
      dtype: int64
    - name: is_repeated_target
      dtype: bool
    - name: correlation_key
      dtype: string
  splits:
    - name: train
      num_examples: 1944887
    - name: validation
      num_examples: 416756
    - name: test
      num_examples: 416781
---

# 🥗 SALAD — SOC Alert Labeled Analysis Dataset

**The first public, unified SOC alert benchmark dataset derived from real network traffic.**

## Dataset Description

SALAD transforms real network traffic from CIC-IDS2017 and UNSW-NB15 into **2,778,424 realistic SOC alerts** with:

| Feature | Description |
|---------|-------------|
| MITRE ATT&CK | 7 tactics, 11 techniques |
| Kill Chain | Lockheed Martin 7 phases |
| Triage Labels | escalate / investigate / suppress |
| Priority | Weighted [0,1] score |
| Difficulty | easy / medium / hard |
| LLM-ready | Natural language descriptions |

## Benchmark Tasks

| Task | Target | Metric | RF Baseline |
|------|--------|--------|-------------|
| Alert Classification | `is_malicious` | F1 | 0.9719 |
| Alert Triage | `triage_decision` | Weighted F1 | 0.9797 |
| Prioritization | `priority_score` | Spearman | 0.7685 |
| Attack Category | `attack_category` | Macro F1 | 0.5673 |

## Usage

```python
from datasets import load_dataset
dataset = load_dataset("username/salad")
```

## Citation

```bibtex
@dataset{salad2026,
  title={SALAD: SOC Alert Labeled Analysis Dataset},
  year={2026},
  license={CC-BY-4.0}
}
```
