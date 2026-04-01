"""
Threat Actor Profile Aggregator - Streamlit Dashboard
Author: Edi-San24
Interactive web interface for ML-enhanced threat intelligence analysis
"""

import streamlit as st
import sys

# Force reload
if 'Threat_Profiler' in sys.modules:
    del sys.modules['Threat_Profiler']

from Threat_Profiler import ThreatActorProfiler
import pandas as pd
import matplotlib.pyplot as plt

# Page configuration
st.set_page_config(
    page_title="Threat Actor Profiler",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# OSINT Intelligence Theme - Dark blues and teals
st.markdown("""
<style>
    /* Main theme */
    .main {
        background-color: #0a1929;
    }
    
    .main-header {
        font-size: 6rem;
        color: #00d4ff;
        font-weight: 900;
        text-align: center;
        margin-bottom: 1.5rem;
        margin-top: 3rem;
        letter-spacing: 8px;
        text-transform: uppercase;
        text-shadow: 0 0 40px rgba(0, 212, 255, 0.6);
        line-height: 1.1;
    }
    
    .sub-header {
        font-size: 2rem;
        color: #7dd3fc;
        text-align: center;
        margin-bottom: 4rem;
        font-weight: 300;
        letter-spacing: 2px;
    }
    
    /* Insight cards */
    .insight-card {
        background: linear-gradient(145deg, #1e3a5f 0%, #0f2744 100%);
        padding: 2rem;
        border-radius: 12px;
        border: 1px solid #2563eb;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px rgba(0, 212, 255, 0.1);
    }
    
    .insight-card h3 {
        color: #60a5fa;
        font-size: 1.2rem;
        margin-bottom: 0.5rem;
    }
    
    .insight-card .stat-highlight {
        font-size: 2.2rem;
        font-weight: bold;
        color: #00d4ff;
        margin: 0.5rem 0;
    }
    
    .insight-card p {
        color: #cbd5e1;
        margin-top: 0.5rem;
        line-height: 1.5;
    }
    
    /* Metrics styling */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem;
        color: #00d4ff;
    }
    
    [data-testid="stMetricLabel"] {
        color: #94a3b8;
        font-size: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize profiler
def load_profiler():
    """Load profiler data"""
    profiler = ThreatActorProfiler()
    profiler.fetch_mitre_data()
    profiler.extract_threat_groups()
    profiler.build_ttp_matrix()
    profiler.calculate_similarity()
    return profiler

with st.spinner('🔄 Loading MITRE ATT&CK Intelligence Database...'):
    profiler = load_profiler()
    groups_df = pd.DataFrame(profiler.groups)

# Header
st.markdown('<p class="main-header">🎯 THREAT ACTOR PROFILER</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">ML-Enhanced Intelligence Analysis Using MITRE ATT&CK Framework</p>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://attack.mitre.org/theme/images/mitre_attack_logo.png", width=220)
    st.markdown("---")
    
    st.markdown("### 📖 About")
    st.info("""
    **Automated Threat Intelligence Platform**
    
    Machine learning-driven analysis of 150+ APT groups 
    from MITRE ATT&CK framework.
    
    **Author:** Edi-San24  
    **Institution:** Northeastern University  
    **Program:** MPS Analytics (ML)  
    **Cert:** CompTIA Security+
    """)
    
    st.markdown("---")
    st.markdown("### 🧭 Pages")
    st.markdown("""
    - 📊 **Home** - Dashboard overview
    - 🔍 **Threat Lookup** - APT profiles  
    - ⚖️ **Comparative** - Multi-actor analysis  
    - 🎯 **Attribution** - Similarity tool
    """)
    
    st.markdown("---")
    st.markdown("### 🔗 Links")
    st.markdown("[GitHub](https://github.com/Edi-San24/threat-actor-profiler)")
    st.markdown("[MITRE ATT&CK](https://attack.mitre.org/)")

# Main metrics - no misleading arrows
st.markdown("## 📊 Intelligence Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="APT Groups Tracked",
        value=len(profiler.groups)
    )

with col2:
    st.metric(
        label="Techniques Analyzed",
        value=profiler.ttp_matrix.shape[1]
    )

with col3:
    avg_techniques = profiler.ttp_matrix.sum(axis=1).mean()
    st.metric(
        label="Avg Techniques/Group",
        value=f"{avg_techniques:.1f}"
    )

with col4:
    malware_count = sum(1 for obj in profiler.data['objects'] if obj['type'] == 'malware')
    tool_count = sum(1 for obj in profiler.data['objects'] if obj['type'] == 'tool')
    st.metric(
        label="Total Arsenal Items",
        value=malware_count + tool_count
    )

st.markdown("---")

# Key insights - emoji-based, clean
st.markdown("## 💡 Key Intelligence Insights")

col_a, col_b, col_c = st.columns(3)

with col_a:
    st.markdown("""
    <div class="insight-card">
        <h3>🎯 Most Sophisticated Actor</h3>
        <p class="stat-highlight">Kimsuky</p>
        <p>109 documented techniques - North Korean intelligence with broadest operational capability spectrum in dataset</p>
    </div>
    """, unsafe_allow_html=True)

with col_b:
    st.markdown("""
    <div class="insight-card">
        <h3>⚔️ Largest Arsenal</h3>
        <p class="stat-highlight">APT29</p>
        <p>49 items (34 malware + 15 tools) - Russian SVR maintains most extensive documented operational toolkit</p>
    </div>
    """, unsafe_allow_html=True)

with col_c:
    st.markdown("""
    <div class="insight-card">
        <h3>🔬 ML Clustering Results</h3>
        <p class="stat-highlight">6 Clusters</p>
        <p>Elite nation-state (33 groups), mid-tier ops (17), specialized threats (116), and 3 outlier families</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Charts with OSINT color scheme
col_left, col_right = st.columns(2)

with col_left:
    st.markdown("### 🔝 Top Threat Actors by Sophistication")
    
    top_groups = profiler.ttp_matrix.sum(axis=1).nlargest(10).sort_values(ascending=True)
    
    fig, ax = plt.subplots(figsize=(8, 6), facecolor='#0a1929')
    ax.set_facecolor('#0f1c2e')
    
    bars = ax.barh(range(len(top_groups)), top_groups.values, 
                   color='#00d4ff', edgecolor='#0ea5e9', linewidth=1.5)
    
    ax.set_yticks(range(len(top_groups)))
    ax.set_yticklabels(top_groups.index, color='#cbd5e1')
    ax.set_xlabel('Technique Count', fontweight='bold', color='#cbd5e1')
    ax.set_title('Top 10 APT Groups', fontweight='bold', color='#00d4ff', fontsize=14)
    ax.grid(axis='x', alpha=0.2, color='#334155')
    ax.tick_params(colors='#cbd5e1')
    ax.spines['bottom'].set_color('#334155')
    ax.spines['top'].set_color('#334155')
    ax.spines['right'].set_color('#334155')
    ax.spines['left'].set_color('#334155')
    
    for i, bar in enumerate(bars):
        width = bar.get_width()
        ax.text(width + 1, bar.get_y() + bar.get_height()/2, 
               f'{int(width)}', ha='left', va='center', fontweight='bold', color='#cbd5e1')
    
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

with col_right:
    st.markdown("### 🌍 Attribution Distribution")
    st.caption("Note: 'Other' includes non-state actors (cybercrime, ransomware) and groups without public attribution")
    
    nation_counts = {
        'Russia': 0,
        'China': 0,
        'North Korea': 0,
        'Iran': 0,
        'Other': 0
    }
    
    nation_keywords = {
        'Russia': ['APT28', 'APT29', 'Turla', 'Sandworm', 'Bear', 'Fancy', 'Cozy', 'Dragonfly'],
        'China': ['APT1', 'APT3', 'APT41', 'Panda', 'Dragon', 'Typhoon', 'Stone'],
        'Iran': ['APT33', 'APT34', 'OilRig', 'Kitten', 'Hound', 'Shamoon'],
        'North Korea': ['APT38', 'Lazarus', 'Kimsuky', 'Andariel', 'Bluenoroff']
    }
    
    for _, row in groups_df.iterrows():
        all_names = [row['name']] + row['aliases']
        categorized = False
        
        for nation, keywords in nation_keywords.items():
            if any(any(kw.lower() in name.lower() for kw in keywords) for name in all_names):
                nation_counts[nation] += 1
                categorized = True
                break
        
        if not categorized:
            nation_counts['Other'] += 1
    
    fig, ax = plt.subplots(figsize=(8, 6), facecolor='#0a1929')
    ax.set_facecolor('#0f1c2e')
    
    # OSINT blue palette
    colors = ['#2563eb', '#00d4ff', '#0ea5e9', '#06b6d4', '#64748b']
    
    wedges, texts, autotexts = ax.pie(
        nation_counts.values(), 
        labels=nation_counts.keys(),
        autopct='%1.1f%%',
        colors=colors,
        startangle=90,
        textprops={'color': '#cbd5e1', 'fontweight': 'bold'}
    )
    
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    
    ax.set_title('APT Groups by Attribution', fontweight='bold', color='#00d4ff')
    st.pyplot(fig)
    plt.close()

st.markdown("---")

# Recently updated
st.markdown("### 🔄 Recent Intelligence Updates")
st.caption("MITRE modifications indicate new threat intelligence, active campaigns, or TTP evolution")

groups_df['modified'] = pd.to_datetime(groups_df['modified'])
recent = groups_df.nlargest(15, 'modified')[['name', 'modified']]
recent['modified'] = recent['modified'].dt.strftime('%Y-%m-%d')

col1, col2 = st.columns([2, 1])

with col1:
    st.dataframe(
        recent.reset_index(drop=True),
        column_config={
            "name": st.column_config.TextColumn("Threat Actor", width="large"),
            "modified": st.column_config.TextColumn("Last MITRE Update", width="medium")
        },
        hide_index=True,
        use_container_width=True
    )

with col2:
    st.markdown("#### 📈 Update Activity")
    most_recent = groups_df['modified'].max()
    thirty_days = most_recent - pd.Timedelta(days=30)
    ninety_days = most_recent - pd.Timedelta(days=90)
    
    recent_30 = len(groups_df[groups_df['modified'] >= thirty_days])
    recent_90 = len(groups_df[(groups_df['modified'] < thirty_days) & (groups_df['modified'] >= ninety_days)])
    older = len(groups_df[groups_df['modified'] < ninety_days])
    
    st.metric("Last 30 Days", recent_30, delta=None)
    st.metric("30-90 Days", recent_90, delta=None)
    st.metric("90+ Days", older, delta=None)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #64748b; padding: 2rem;'>
    <p style='font-size: 1.1rem; color: #94a3b8;'><strong>Threat Actor Profile Aggregator</strong></p>
    <p style='color: #64748b;'>Phase 1: TTP Analysis • Phase 2: Arsenal Mapping • Phase 3: Enhanced Exports</p>
    <p style='color: #475569;'>Built with Python, scikit-learn, and Streamlit | Data: MITRE ATT&CK Framework</p>
</div>
""", unsafe_allow_html=True)