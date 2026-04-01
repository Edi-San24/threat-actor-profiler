"""
Attribution Tool Page - Similarity-Based Threat Actor Attribution
"""

import streamlit as st
import sys

if 'Threat_Profiler' in sys.modules:
    del sys.modules['Threat_Profiler']

from Threat_Profiler import ThreatActorProfiler
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

st.set_page_config(page_title="Attribution Tool", page_icon="🎯", layout="wide")

# Apply OSINT theme
st.markdown("""
<style>
    .main { background-color: #0a1929; }
    .tool-header {
        font-size: 2.5rem;
        color: #00d4ff;
        font-weight: bold;
        margin-bottom: 1rem;
    }
    .high-confidence {
        background-color: #166534;
        padding: 0.5rem;
        border-radius: 0.5rem;
        color: white;
    }
    .moderate-confidence {
        background-color: #a16207;
        padding: 0.5rem;
        border-radius: 0.5rem;
        color: white;
    }
    .low-confidence {
        background-color: #991b1b;
        padding: 0.5rem;
        border-radius: 0.5rem;
        color: white;
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

# Header
st.markdown("# 🎯 Attribution Tool")
st.markdown("Input observed TTPs to identify likely threat actors using ML-based similarity analysis")
st.markdown("---")

# Instructions
with st.expander("ℹ️ How to Use This Tool", expanded=False):
    st.markdown("""
    **Attribution Workflow:**
    
    1. **Select Techniques** - Choose TTPs you've observed in an attack or investigation
    2. **Analyze** - Tool calculates similarity against 150+ known APT groups
    3. **Review Results** - Get ranked list of likely threat actors with confidence scores
    4. **Investigate Further** - Use top matches as attribution leads for deeper analysis
    
    **Confidence Levels:**
    - 🟢 **High (>60%)**: Strong TTP overlap - high-confidence attribution lead
    - 🟡 **Moderate (40-60%)**: Significant similarity - warrants investigation
    - 🔴 **Low (<40%)**: Some shared tactics - possible but requires corroboration
    
    **Note:** This is a starting point for attribution, not definitive proof. Always corroborate with additional intelligence sources.
    """)

st.markdown("---")

# Get all unique techniques from dataset
all_techniques = set()
technique_names = {}

for group in profiler.groups:
    techs = profiler.get_group_techniques(group['name'])
    if not techs.empty:
        for _, row in techs.iterrows():
            tech_id = row['technique_id']
            all_techniques.add(tech_id)
            if tech_id not in technique_names:
                technique_names[tech_id] = row['technique_name']

# Create searchable technique list
technique_options = [f"{tid} - {technique_names[tid]}" for tid in sorted(all_techniques)]

# Technique selection
st.markdown("## 🔍 Select Observed Techniques")
st.caption("Choose the TTPs you've observed in your investigation")

selected_techniques = st.multiselect(
    "Search and select techniques:",
    options=technique_options,
    help="Start typing a technique ID or name to search"
)

# Extract just the IDs
selected_ids = [t.split(' - ')[0] for t in selected_techniques]

st.markdown(f"**Selected:** {len(selected_ids)} technique(s)")

if len(selected_ids) > 0:
    st.markdown("---")
    
    # Calculate similarity
    st.markdown("## 🎯 Attribution Analysis Results")
    
    with st.spinner('Calculating similarity scores against APT database...'):
        # Create binary vector for observed TTPs
        observed_vector = pd.Series(0, index=profiler.ttp_matrix.columns)
        for tech_id in selected_ids:
            if tech_id in observed_vector.index:
                observed_vector[tech_id] = 1
        
        # Calculate similarity against all groups
        similarities = {}
        for group_name in profiler.ttp_matrix.index:
            group_vector = profiler.ttp_matrix.loc[group_name]
            
            # Cosine similarity
            dot_product = (observed_vector * group_vector).sum()
            norm_observed = np.sqrt((observed_vector ** 2).sum())
            norm_group = np.sqrt((group_vector ** 2).sum())
            
            if norm_observed > 0 and norm_group > 0:
                similarity = dot_product / (norm_observed * norm_group)
                similarities[group_name] = similarity
        
        # Sort by similarity
        sorted_matches = sorted(similarities.items(), key=lambda x: x[1], reverse=True)[:15]
    
    # Display results
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### Top 15 Attribution Candidates")
        
        # Build results dataframe
        results = []
        for group, score in sorted_matches:
            confidence = 'High' if score > 0.6 else 'Moderate' if score > 0.4 else 'Low'
            results.append({
                'Rank': len(results) + 1,
                'Threat Actor': group,
                'Similarity': score,
                'Similarity %': score * 100,
                'Confidence': confidence
            })
        
        results_df = pd.DataFrame(results)
        
        st.dataframe(
            results_df[['Rank', 'Threat Actor', 'Similarity %', 'Confidence']],
            column_config={
                "Rank": st.column_config.NumberColumn("#", width="small"),
                "Threat Actor": st.column_config.TextColumn("Threat Actor", width="large"),
                "Similarity %": st.column_config.ProgressColumn(
                    "Similarity",
                    format="%.1f%%",
                    min_value=0,
                    max_value=100
                ),
                "Confidence": st.column_config.TextColumn("Confidence", width="small")
            },
            hide_index=True,
            use_container_width=True
        )
    
    with col2:
        st.markdown("### 📊 Confidence Distribution")
        
        high_count = len([r for r in results if r['Confidence'] == 'High'])
        moderate_count = len([r for r in results if r['Confidence'] == 'Moderate'])
        low_count = len([r for r in results if r['Confidence'] == 'Low'])
        
        st.metric("🟢 High Confidence", high_count, help="Similarity >60%")
        st.metric("🟡 Moderate Confidence", moderate_count, help="Similarity 40-60%")
        st.metric("🔴 Low Confidence", low_count, help="Similarity <40%")
        
        st.markdown("---")
        
        # Top match detail
        if sorted_matches:
            top_group, top_score = sorted_matches[0]
            st.markdown("#### 🏆 Top Match")
            st.markdown(f"**{top_group}**")
            st.markdown(f"Similarity: **{top_score:.1%}**")
            
            # Show top match's total TTPs
            top_techs = profiler.get_group_techniques(top_group)
            st.markdown(f"Known TTPs: {len(top_techs)}")
    
    st.markdown("---")
    
    # Visualization
    st.markdown("### 📈 Attribution Candidate Rankings")
    
    fig, ax = plt.subplots(figsize=(10, 8), facecolor='#0a1929')
    ax.set_facecolor('#0f1c2e')
    
    # Get top 10 for chart
    top_10_groups = [g for g, s in sorted_matches[:10]]
    top_10_scores = [s * 100 for g, s in sorted_matches[:10]]
    
    # Color by confidence
    colors = []
    for score in top_10_scores:
        if score > 60:
            colors.append('#10b981')  # Green
        elif score > 40:
            colors.append('#f59e0b')  # Orange
        else:
            colors.append('#ef4444')  # Red
    
    bars = ax.barh(range(len(top_10_groups)), top_10_scores, color=colors, edgecolor='#cbd5e1')
    
    ax.set_yticks(range(len(top_10_groups)))
    ax.set_yticklabels(top_10_groups, color='#cbd5e1')
    ax.set_xlabel('Similarity (%)', color='#cbd5e1', fontweight='bold')
    ax.set_title('Top 10 Attribution Candidates', color='#00d4ff', fontweight='bold', fontsize=14)
    ax.tick_params(colors='#cbd5e1')
    ax.grid(axis='x', alpha=0.2, color='#334155')
    
    for spine in ax.spines.values():
        spine.set_color('#334155')
    
    # Add percentage labels
    for i, bar in enumerate(bars):
        width = bar.get_width()
        ax.text(width + 1, bar.get_y() + bar.get_height()/2,
               f'{width:.1f}%',
               ha='left', va='center', color='#cbd5e1', fontweight='bold')
    
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()
    
    # Attribution guidance
    st.markdown("---")
    st.success("""
    **🎯 Next Steps for Attribution:**
    
    1. **Review top 3-5 matches** - Check if they align with other indicators (infrastructure, victimology, timing)
    2. **Examine TTP details** - Use Threat Lookup page to see full profiles of top candidates
    3. **Cross-reference intelligence** - Corroborate with external threat intel, OSINT, or government advisories
    4. **Consider multiple matches** - If several groups show moderate similarity, look for additional distinguishing factors
    5. **Document confidence** - Report attribution with appropriate confidence levels based on similarity scores
    """)

else:
    st.info("👆 Select techniques above to begin attribution analysis")

# Footer
st.markdown("---")
st.caption("💡 This tool uses cosine similarity to match observed TTPs against known threat actor patterns - a starting point for intelligence-driven attribution")
