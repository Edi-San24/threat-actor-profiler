# threat-actor-profiler
ML-enhanced OSINT tool for threat intelligence analysis using MITRE ATT&amp;CK framework

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
