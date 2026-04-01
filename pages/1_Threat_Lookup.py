"""
Threat Lookup Page - Individual APT Profile Viewer
"""

import streamlit as st
import sys

if 'Threat_Profiler' in sys.modules:
    del sys.modules['Threat_Profiler']

from Threat_Profiler import ThreatActorProfiler
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="Threat Lookup", page_icon="🔍", layout="wide")

# Apply OSINT theme
st.markdown("""
<style>
    .main { background-color: #0a1929; }
    .profile-header {
        font-size: 2.5rem;
        color: #00d4ff;
        font-weight: bold;
        margin-bottom: 1rem;
    }
    .section-header {
        color: #60a5fa;
        font-size: 1.5rem;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Load profiler - no caching
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
st.markdown("# 🔍 Threat Actor Lookup")
st.markdown("Search and analyze individual APT groups with detailed intelligence profiles")
st.markdown("---")

# Group selection
col1, col2 = st.columns([3, 1])

with col1:
    group_names = sorted([g['name'] for g in profiler.groups])
    selected_group = st.selectbox(
        "Select Threat Actor Group:",
        options=group_names,
        index=group_names.index("APT29") if "APT29" in group_names else 0
    )

with col2:
    st.markdown("#### Quick Stats")
    if selected_group:
        techs = profiler.get_group_techniques(selected_group)
        st.metric("Techniques", len(techs))

st.markdown("---")

# Display profile
if selected_group:
    # Get group data
    group_data = None
    for g in profiler.groups:
        if g['name'] == selected_group or selected_group in g.get('aliases', []):
            group_data = g
            break
    
    if group_data:
        # Header section
        st.markdown(f'<p class="profile-header">{group_data["name"]}</p>', unsafe_allow_html=True)
        
        # Basic info in columns
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**📛 Aliases:**")
            if group_data['aliases']:
                for alias in group_data['aliases'][:5]:
                    st.markdown(f"• {alias}")
                if len(group_data['aliases']) > 5:
                    st.markdown(f"*...and {len(group_data['aliases']) - 5} more*")
            else:
                st.markdown("*None documented*")
        
        with col2:
            st.markdown("**📅 Timeline:**")
            st.markdown(f"**First Observed:** {group_data['created'][:10]}")
            st.markdown(f"**Last Updated:** {group_data['modified'][:10]}")
        
        with col3:
            techniques = profiler.get_group_techniques(selected_group)
            st.markdown("**📊 Capabilities:**")
            st.markdown(f"• **{len(techniques)}** Documented Techniques")
        
        # Description
        st.markdown('<p class="section-header">📋 Intelligence Summary</p>', unsafe_allow_html=True)
        st.markdown(group_data['description'])
        
        st.markdown("---")
        
        # TTPs Section
        st.markdown('<p class="section-header">🎯 Tactics, Techniques & Procedures (TTPs)</p>', unsafe_allow_html=True)
        
        if not techniques.empty:
            col_left, col_right = st.columns([2, 1])
            
            with col_left:
                st.markdown("**TTP Database:**")
                st.dataframe(
                    techniques[['technique_id', 'technique_name', 'tactic']],
                    column_config={
                        "technique_id": "ID",
                        "technique_name": "Technique",
                        "tactic": "Tactic"
                    },
                    hide_index=True,
                    use_container_width=True,
                    height=400
                )
            
            with col_right:
                st.markdown("**Tactic Distribution:**")
                
                # TTP distribution chart
                tactic_counts = {}
                for tactics in techniques['tactic']:
                    for tactic in tactics.split(', '):
                        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                
                if tactic_counts:
                    fig, ax = plt.subplots(figsize=(6, 6), facecolor='#0a1929')
                    ax.set_facecolor('#0f1c2e')
                    
                    tactics = list(tactic_counts.keys())
                    counts = list(tactic_counts.values())
                    
                    bars = ax.barh(tactics, counts, color='#00d4ff', edgecolor='#0ea5e9')
                    ax.set_xlabel('Count', color='#cbd5e1', fontweight='bold')
                    ax.set_title('TTP Focus Areas', color='#00d4ff', fontweight='bold')
                    ax.tick_params(colors='#cbd5e1')
                    ax.grid(axis='x', alpha=0.2, color='#334155')
                    
                    for spine in ax.spines.values():
                        spine.set_color('#334155')
                    
                    for bar in bars:
                        width = bar.get_width()
                        ax.text(width + 0.3, bar.get_y() + bar.get_height()/2, 
                               f'{int(width)}', ha='left', va='center', 
                               color='#cbd5e1', fontweight='bold')
                    
                    plt.tight_layout()
                    st.pyplot(fig)
                    plt.close()
        else:
            st.info("No TTPs documented for this group")
        
        st.markdown("---")
        
        # Similarity Section
        st.markdown('<p class="section-header">🔗 Operationally Similar Groups</p>', unsafe_allow_html=True)
        st.caption("Groups with shared TTP patterns - useful for attribution and threat hunting")
        
        similar = profiler.find_similar_groups(selected_group, top_n=10)
        
        if not similar.empty:
            # Filter out perfect matches (aliases)
            actual_similar = [(g, s) for g, s in similar.items() if s < 1.0]
            
            if actual_similar:
                similar_df = pd.DataFrame(actual_similar, columns=['Group', 'Similarity'])
                similar_df['Similarity %'] = (similar_df['Similarity'] * 100).round(1)
                similar_df['Confidence'] = similar_df['Similarity'].apply(
                    lambda x: 'High' if x > 0.5 else 'Moderate' if x > 0.3 else 'Low'
                )
                
                st.dataframe(
                    similar_df[['Group', 'Similarity %', 'Confidence']],
                    column_config={
                        "Group": "Threat Actor",
                        "Similarity %": st.column_config.ProgressColumn(
                            "Similarity",
                            format="%.1f%%",
                            min_value=0,
                            max_value=100
                        ),
                        "Confidence": st.column_config.TextColumn("Attribution Confidence")
                    },
                    hide_index=True,
                    use_container_width=True
                )
                
                st.info("💡 **Attribution Guidance:** Similarity >50% warrants high-confidence investigation. Scores 30-50% suggest possible attribution requiring additional corroboration.")
            else:
                st.info("Selected group is an alias - showing base group profile")
        else:
            st.warning("Similarity data not available")

# Footer
st.markdown("---")
st.caption("💡 Use this page to research specific threat actors and identify potential attribution leads based on TTP similarity")
