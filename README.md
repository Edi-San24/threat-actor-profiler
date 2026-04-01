# Threat Actor Profile Aggregator

ML-enhanced OSINT tool for automated threat intelligence analysis using the MITRE ATT&CK framework.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)

---

## Overview

The Threat Actor Profile Aggregator is an automated intelligence collection and analysis system that profiles Advanced Persistent Threat (APT) groups using publicly available data from the MITRE ATT&CK framework. The system applies machine learning to quantify operational similarities, map arsenal capabilities, analyze sector targeting patterns, and predict nation-state attribution from observed TTPs — producing structured intelligence products suitable for threat hunting, detection engineering, and strategic risk assessment.

### Key Features

- **Automated Data Collection**: Extracts structured threat intelligence on 150+ APT groups from MITRE ATT&CK's public CTI repository
- **ML-Enhanced Analysis**: Cosine similarity and K-Means clustering identify operational relationships and threat actor families
- **Arsenal Profiling**: Maps 600+ malware families and tools to specific threat actors, revealing capability levels and infrastructure sharing
- **Sector Targeting Analysis**: Identifies which industries each threat actor targets across 10 verticals using MITRE description analysis
- **Network Graph Visualization**: Maps infrastructure sharing relationships between threat actors via shared malware and tools
- **Nation-State Attribution**: Random Forest classifier predicts sponsoring nation-state from observed TTP patterns
- **Interactive Dashboard**: Streamlit web application for live threat actor lookup, comparison, and attribution analysis
- **Production-Quality Exports**: Timestamped CSV outputs with metadata, summary statistics, and data dictionary

---

## Methodology

**[I] TTP Analysis**
Extracts structured threat data from MITRE ATT&CK, engineers binary feature matrices (groups × techniques), calculates cosine similarity to quantify operational overlap, and applies K-Means and hierarchical clustering to identify threat actor families.

**[II] Arsenal & Infrastructure Analysis**
Extracts malware families and tools from MITRE, maps arsenal components to specific threat actors, identifies shared infrastructure between groups, and compares sophistication across nation-state programs using malware-to-tool ratios.

**[III] Data Export Framework**
Exports all analysis outputs to organized subdirectories (raw / processed / summaries) with timestamps, metadata JSON, summary statistics, and a data dictionary documenting every output file.

**[IV] Advanced Intelligence Analysis**
Extends the profiling system with three complementary analytical capabilities: sector and victim targeting analysis scans MITRE descriptions for industry-specific keywords across 10 verticals and cross-references findings with nation-state attribution; network graph visualization constructs an infrastructure sharing graph connecting threat actors via shared malware and tools; and a nation-state attribution classifier trains a Random Forest model on the TTP binary feature space, generating confidence scores across four nation-state programs with feature importance analysis identifying the most diagnostic techniques.

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Jupyter Notebook

### Setup
```bash
# Clone the repository
git clone https://github.com/Edi-San24/threat-actor-profiler.git
cd threat-actor-profiler

# Install dependencies
pip install -r requirements.txt

# Create output directory
mkdir outputs
```

### Dependencies
```
pandas==2.1.0
numpy==1.24.3
matplotlib==3.7.2
seaborn==0.12.2
scikit-learn==1.3.0
scipy==1.11.2
requests==2.31.0
jupyter==1.0.0
streamlit==1.29.0
networkx
```

---

## Usage

### Jupyter Notebook (Full Analysis)
```bash
jupyter notebook OSINT_Profiler.ipynb
```

### Streamlit Dashboard
```bash
streamlit run app.py
```

### Python Module
```python
from Threat_Profiler import ThreatActorProfiler

profiler = ThreatActorProfiler()
profiler.fetch_mitre_data()
profiler.extract_threat_groups()

# TTP Analysis
profile = profiler.generate_profile("APT29")
profiler.find_similar_groups("APT29", top_n=10)
profiler.plot_threat_landscape(n_clusters=6)

# Arsenal Analysis
arsenal = profiler.get_group_arsenal("APT29")
profiler.plot_arsenal_comparison(["APT29", "APT28", "Lazarus Group"])

# Sector Targeting
profiler.plot_sector_distribution()
profiler.nation_state_sector_analysis()

# Network Graph
profiler.plot_malware_network(min_shared=2, top_n=40)

# Attribution
results = profiler.predict_threat_actor(['T1566.001', 'T1059.001', 'T1003.001'])
```

---

## Key Findings

**Nation-State Operational Patterns**
- **Russia**: Favors PowerShell, registry persistence, and living-off-the-land techniques
- **China**: Prioritizes credential theft and lateral movement with the broadest sector targeting spread across 9 verticals
- **North Korea**: Heavy custom malware reliance despite resource constraints — 85% malware composition in Lazarus Group's arsenal
- **Iran**: Concentrated Energy sector targeting aligned with documented regional geopolitical objectives

**Arsenal Sophistication**
- APT29 maintains the most extensive documented toolkit (49 items: 34 custom malware + 15 tools)
- Lazarus Group demonstrates 85% custom malware composition despite sanctions constraints
- menuPass leads infrastructure connectivity with 69 shared tool relationships across the network
- Mimikatz (52 groups), Cobalt Strike (29 groups), and PsExec (39 groups) represent the most widely shared offensive tools

**Sector Targeting**
- Government (91 groups) and Technology (78 groups) are the most targeted sectors globally
- North Korea uniquely concentrates Finance targeting reflecting sanctions evasion objectives
- Iran leads Energy sector targeting consistent with documented Gulf infrastructure campaigns

**Clustering**
- 6 operational clusters identified — Cluster 1 (33 groups, 80+ techniques) represents elite nation-state operations
- Cluster 2 (116 groups, 68% of dataset) reflects specialized actors with focused operational mandates
- North Korea and China share operational space in Cluster 1 despite distinct national programs, consistent with documented misattribution cases

**Attribution Model**
- Nation-state classifier achieves 50% accuracy — double random chance (25%) with 36 labeled samples
- Iran demonstrates highest precision (1.0); North Korea most difficult to classify due to TTP overlap with Chinese actors
- Most diagnostic techniques for attribution are low-frequency, program-specific TTPs rather than commonly used ones

---

## Project Structure

```
threat-actor-profiler/
├── Threat_Profiler.py          # Core analysis module
├── OSINT_Profiler.ipynb        # Full analysis notebook
├── app.py                      # Streamlit dashboard
├── requirements.txt
├── README.md
├── pages/
│   ├── 1_Threat_Lookup.py
│   ├── 2_Comparative_Analysis.py
│   └── 3_Attribution_Tool.py
└── outputs/
    ├── raw/
    ├── processed/
    └── summaries/
```

---

## Data Source

- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **MITRE CTI Repository**: https://github.com/mitre/cti

All data sourced from MITRE's open CTI repository in accordance with their terms of use.

---

## License

MIT License — see LICENSE file for details.

---

## Author

**Edi-San24**
---

## Acknowledgments

- **MITRE Corporation** for maintaining the ATT&CK framework and public CTI repository
- **Northeastern University** for supporting experiential learning opportunities
- **Open-source community** for the Python libraries that made this possible

---

## Disclaimer

This tool is designed for educational and defensive cybersecurity purposes. It analyzes publicly available threat intelligence to support security operations, threat hunting, and risk assessment. The author is not responsible for any misuse of this tool.

---

*Built with Python, scikit-learn, and a passion for threat intelligence.*
