# Threat Actor Profile Aggregator

ML-enhanced OSINT tool for automated threat intelligence analysis using the MITRE ATT&CK framework.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)

---

## Overview

The Threat Actor Profile Aggregator is an automated intelligence collection and analysis tool designed to profile Advanced Persistent Threat (APT) groups using publicly available data from the MITRE ATT&CK framework. The tool applies machine learning techniques to quantify operational similarities between threat actors, enabling data-driven attribution analysis for cybersecurity professionals.

### Key Features

- **Automated Data Collection**: Extracts structured threat intelligence on 150+ APT groups from MITRE ATT&CK's public CTI repository
- **ML-Enhanced Analysis**: Implements cosine similarity and K-Means clustering to identify operational relationships between threat actors
- **Attribution Support**: Generates similarity scores to assist in threat attribution when analyzing unknown attacks
- **Intelligence Visualization**: Creates professional-grade visualizations including PCA threat landscapes, hierarchical dendrograms, and TTP heatmaps
- **Exportable Reports**: Produces CSV outputs and intelligence profiles suitable for threat hunting and detection engineering

---

## Methodology

### 1. Data Collection
Retrieves threat actor data from MITRE ATT&CK's public GitHub repository, parsing 600+ techniques and their relationships to APT groups.

### 2. Feature Engineering
Transforms categorical threat intelligence into binary feature matrices where each row represents a threat actor and each column represents a technique (1 = uses technique, 0 = doesn't use).

### 3. Similarity Analysis
Applies cosine similarity to measure operational overlap between groups, producing quantifiable scores (0-1) indicating shared tactics.

### 4. Clustering
Uses K-Means and hierarchical clustering to identify "threat actor families" with related operational tradecraft.

### 5. Visualization
Generates intelligence products including:
- **PCA Threat Landscape**: 2D map showing all threat actors clustered by similarity
- **Hierarchical Dendrogram**: Family tree revealing group relationships
- **TTP Distribution Charts**: Bar charts showing tactical focus areas per group

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
```

---

## Usage

### Quick Start (Python Script)
```python
from threat_profiler import ThreatActorProfiler

# Initialize profiler
profiler = ThreatActorProfiler()

# Download MITRE ATT&CK data
profiler.fetch_mitre_data()

# Extract all threat groups
groups = profiler.extract_threat_groups()
print(f"Loaded {len(groups)} threat actors")

# Profile a specific APT group
profile = profiler.generate_profile("APT29")

# Find similar threat actors
profiler.find_similar_groups("APT29", top_n=10)

# Generate visualizations
profiler.plot_ttp_distribution("APT29")
profiler.plot_threat_landscape(n_clusters=6)
profiler.plot_similarity_heatmap(top_n=20)
```

### Full Analysis (Jupyter Notebook)

For comprehensive analysis with detailed explanations and visualizations, open `osint_profiler.ipynb` in Jupyter:
```bash
jupyter notebook osint_profiler.ipynb
```

The notebook includes:
- Complete exploratory data analysis
- Individual threat actor profiling
- ML clustering analysis
- Nation-state operational comparison
- Intelligence assessment summary

---

## Key Findings

### Analytical Insights

**Nation-State Operational Patterns:**
- **Russia**: Favors PowerShell, registry persistence, and living-off-the-land techniques
- **China**: Prioritizes credential theft (LSASS dumps, Pass-the-Hash) and lateral movement
- **North Korea**: Emphasizes spearphishing, command-line operations, and tool deployment
- **Iran**: Focuses on credential harvesting from files and caches with data archival

**Threat Actor Families:**
ML clustering reveals 5-7 distinct operational families based on shared TTP patterns, enabling more effective threat hunting across related groups.

**Attribution Value:**
Cosine similarity scoring provides quantifiable metrics (e.g., "Unknown attack shows 87% similarity to APT29 patterns") for data-driven attribution analysis.

---

## Use Cases

### Threat Hunting
Use similarity scores to guide hunting for related APT activity when investigating unknown intrusions.

### Detection Engineering
Build detection rules covering entire threat actor families rather than individual groups.

### Risk Assessment
Understand which threat actors target specific sectors and their operational sophistication levels.

### Strategic Intelligence
Track evolution of threat actor capabilities and emerging TTP adoption patterns.

---

## Future Enhancements (Phase 2)

- **CISA Integration**: Add government threat advisories and vulnerability intelligence
- **Temporal Analysis**: Track TTP evolution over time to identify emerging techniques
- **News Feed Integration**: Incorporate recent threat actor activity from security blogs
- **Malware Mapping**: Link threat actors to specific malware families
- **Predictive Modeling**: Build models to predict emerging technique adoption

---

## Data Source

This project uses publicly available threat intelligence from:
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **MITRE CTI Repository**: https://github.com/mitre/cti

All data is sourced from MITRE's open CTI repository and is used in accordance with their terms of use.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Author

**Edison Chalas**  
Graduate Student - MPS in Analytics (Applied Machine Intelligence)  
Northeastern University
**Certifications:** 

CompTIA Security+ | Exp: 2028
---

## Acknowledgments

- **MITRE Corporation** for maintaining the ATT&CK framework and public CTI repository
- **Northeastern University** for supporting experiential learning opportunities
- **Open-source community** for the excellent Python libraries (pandas, scikit-learn, matplotlib)

---

## Disclaimer

This tool is designed for educational and defensive cybersecurity purposes. It analyzes publicly available threat intelligence to support security operations, threat hunting, and risk assessment activities. The author is not responsible for any misuse of this tool.

---
