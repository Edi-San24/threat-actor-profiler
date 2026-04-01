"""
Comparative Analysis Page - Multi-Group Comparison
"""

import streamlit as st
import sys

if 'Threat_Profiler' in sys.modules:
    del sys.modules['Threat_Profiler']

from Threat_Profiler import ThreatActorProfiler
from matplotlib.colors import LinearSegmentedColormap
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

st.set_page_config(page_title="Comparative Analysis", page_icon="⚖️", layout="wide")

# Apply OSINT theme
st.markdown("""
<style>
    .main { background-color: #0a1929; }
    .comparison-header {
        font-size: 2rem;
        color: #00d4ff;
        font-weight: bold;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Load profiler
def get_profiler():
    p = ThreatActorProfiler()
    p.fetch_mitre_data()
    p.extract_threat_groups()
    p.build_ttp_matrix()
    p.calculate_similarity()
    return p

with st.spinner('Loading threat intelligence data...'):
    profiler = get_profiler()
    groups_df = pd.DataFrame(profiler.groups)

# Header
st.markdown("# ⚖️ Comparative Analysis")
st.markdown("Compare multiple threat actors side-by-side to identify patterns and relationships")
st.markdown("---")

# Group selection
group_names = sorted([g['name'] for g in profiler.groups])

selected_groups = st.multiselect(
    "Select 2-6 Threat Actor Groups to Compare:",
    options=group_names,
    default=["APT29", "APT28", "Lazarus Group"] if all(g in group_names for g in ["APT29", "APT28", "Lazarus Group"]) else group_names[:3],
    max_selections=6
)

if len(selected_groups) < 2:
    st.warning("⚠️ Please select at least 2 groups for comparison")
    st.stop()

st.markdown("---")

# Comparison metrics
st.markdown("## 📊 Capability Comparison")

# Build comparison data
comparison_data = []
for group in selected_groups:
    techs = profiler.get_group_techniques(group)
    
    # Get group info
    group_info = next((g for g in profiler.groups if g['name'] == group), None)
    
    if group_info:
        comparison_data.append({
            'Threat Actor': group,
            'Total Techniques': len(techs),
            'First Observed': group_info['created'][:10],
            'Last Updated': group_info['modified'][:10],
            'Aliases': len(group_info.get('aliases', []))
        })

comparison_df = pd.DataFrame(comparison_data)

# Display comparison table
st.dataframe(
    comparison_df,
    column_config={
        "Threat Actor": st.column_config.TextColumn("Threat Actor", width="large"),
        "Total Techniques": st.column_config.NumberColumn("Techniques", format="%d"),
        "First Observed": "First Observed",
        "Last Updated": "Last Updated",
        "Aliases": st.column_config.NumberColumn("Known Aliases", format="%d")
    },
    hide_index=True,
    use_container_width=True
)

st.markdown("---")

# Technique count comparison chart
st.markdown("## 📈 TTP Portfolio Comparison")

fig, ax = plt.subplots(figsize=(10, 6), facecolor='#0a1929')
ax.set_facecolor('#0f1c2e')

technique_counts = [row['Total Techniques'] for row in comparison_data]
x = np.arange(len(selected_groups))

bars = ax.bar(x, technique_counts, color='#00d4ff', edgecolor='#0ea5e9', linewidth=1.5)

ax.set_xlabel('Threat Actor', color='#cbd5e1', fontweight='bold')
ax.set_ylabel('Technique Count', color='#cbd5e1', fontweight='bold')
ax.set_title('TTP Portfolio Size Comparison', color='#00d4ff', fontweight='bold', fontsize=14)
ax.set_xticks(x)
ax.set_xticklabels(selected_groups, rotation=45, ha='right', color='#cbd5e1')
ax.tick_params(colors='#cbd5e1')
ax.grid(axis='y', alpha=0.2, color='#334155')

for spine in ax.spines.values():
    spine.set_color('#334155')

# Add value labels
for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 1,
           f'{int(height)}',
           ha='center', va='bottom', color='#cbd5e1', fontweight='bold')

plt.tight_layout()
st.pyplot(fig)
plt.close()

st.markdown("---")

# Similarity matrix
st.markdown("## 🔗 Operational Similarity Matrix")
st.caption("Shows TTP overlap between selected groups - higher values indicate similar operational patterns")

if profiler.similarity_matrix is not None:
    # Get similarity subset
    similarity_subset = profiler.similarity_matrix.loc[selected_groups, selected_groups]
    
    fig, ax = plt.subplots(figsize=(10, 8), facecolor='#0a1929')
    ax.set_facecolor('#0f1c2e')
    
    # Custom OSINT colormap: dark navy (low) -> cyan (high)
    osint_cmap = LinearSegmentedColormap.from_list(
        'osint', ['#0a1929', '#0d2d4a', '#0ea5e9', '#00d4ff']
    )
    
    # Heatmap
    im = ax.imshow(similarity_subset.values, cmap=osint_cmap, aspect='auto', vmin=0, vmax=1)
    
    # Colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Similarity Score', color='#cbd5e1', fontweight='bold')
    cbar.ax.tick_params(colors='#cbd5e1')
    cbar.ax.yaxis.label.set_color('#cbd5e1')
    
    # Set ticks
    ax.set_xticks(np.arange(len(selected_groups)))
    ax.set_yticks(np.arange(len(selected_groups)))
    ax.set_xticklabels(selected_groups, rotation=45, ha='right', color='#cbd5e1')
    ax.set_yticklabels(selected_groups, color='#cbd5e1')
    
    # Add values in cells
    for i in range(len(selected_groups)):
        for j in range(len(selected_groups)):
            value = similarity_subset.iloc[i, j]
            color = 'white' if value > 0.5 else '#cbd5e1'
            ax.text(j, i, f'{value:.3f}',
                   ha="center", va="center", color=color, fontweight='bold')
    
    ax.set_title('TTP Similarity Scores', color='#00d4ff', fontweight='bold', fontsize=14)
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()
    
    # Interpretation guide
    st.info("""
    **💡 Interpretation Guide:**
    - **0.6-1.0** (Bright Cyan): High similarity - possibly shared resources or same organizational unit
    - **0.4-0.6** (Medium Blue): Moderate similarity - similar operational patterns
    - **0.2-0.4** (Dark Blue): Some shared tactics - potential operational connections
    - **0.0-0.2** (Near Black): Minimal overlap - distinct operational approaches
    """)

st.markdown("---")

# TTP overlap analysis
st.markdown("## 🎯 Shared Technique Analysis")
st.caption("Techniques used by multiple groups in your selection")

# Find shared techniques
all_techniques = {}
for group in selected_groups:
    techs = profiler.get_group_techniques(group)
    if not techs.empty:
        for tech_id in techs['technique_id'].values:
            if tech_id not in all_techniques:
                all_techniques[tech_id] = {'count': 0, 'groups': [], 'name': ''}
            all_techniques[tech_id]['count'] += 1
            all_techniques[tech_id]['groups'].append(group)
            if not all_techniques[tech_id]['name']:
                all_techniques[tech_id]['name'] = techs[techs['technique_id'] == tech_id]['technique_name'].values[0]

# Filter to techniques used by 2+ groups
shared_techniques = {tid: data for tid, data in all_techniques.items() if data['count'] >= 2}

if shared_techniques:
    # Sort by frequency
    sorted_shared = sorted(shared_techniques.items(), key=lambda x: x[1]['count'], reverse=True)
    
    st.markdown(f"**Found {len(shared_techniques)} shared techniques**")
    
    # Show top 15 most shared
    shared_df = pd.DataFrame([
        {
            'Technique ID': tid,
            'Technique Name': data['name'],
            'Used By': f"{data['count']}/{len(selected_groups)} groups",
            'Groups': ', '.join(data['groups'])
        }
        for tid, data in sorted_shared[:15]
    ])
    
    st.dataframe(
        shared_df,
        column_config={
            "Technique ID": st.column_config.TextColumn("ID", width="small"),
            "Technique Name": st.column_config.TextColumn("Technique", width="large"),
            "Used By": st.column_config.TextColumn("Shared By", width="small"),
            "Groups": st.column_config.TextColumn("Threat Actors", width="large")
        },
        hide_index=True,
        use_container_width=True
    )
    
    if len(sorted_shared) > 15:
        st.caption(f"...and {len(sorted_shared) - 15} more shared techniques")
else:
    st.info("No techniques shared across selected groups")

# Footer
st.markdown("---")
st.caption("💡 Use this page to identify operational patterns and TTP overlaps across multiple threat actors")
