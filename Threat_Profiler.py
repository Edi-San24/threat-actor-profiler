"""
Threat Actor Profile Aggregator
Author: Edi-San24
ML-enhanced threat intelligence analysis using MITRE ATT&CK
"""

import requests
import pandas as pd
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import KMeans, DBSCAN
from sklearn.decomposition import PCA
from scipy.cluster.hierarchy import dendrogram, linkage
import warnings
warnings.filterwarnings('ignore')


class ThreatActorProfiler:

    def __init__(self):
        self.mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.data = None
        self.groups = []
        self.ttp_matrix = None
        self.similarity_matrix = None

    def fetch_mitre_data(self):
        """Download MITRE ATT&CK dataset"""
        print("[*] Fetching MITRE ATT&CK data...")
        response = requests.get(self.mitre_url)
        response.raise_for_status()
        self.data = response.json()
        print(f"[+] Loaded {len(self.data['objects'])} objects")
        return True

    def extract_threat_groups(self):
        """Get all APT groups from dataset"""
        print("[*] Extracting threat groups...")
        self.groups = []
        for obj in self.data['objects']:
            if obj['type'] == 'intrusion-set':
                self.groups.append({
                    'id': obj['id'],
                    'name': obj['name'],
                    'aliases': obj.get('aliases', []),
                    'description': obj.get('description', 'N/A'),
                    'created': obj.get('created', 'Unknown'),
                    'modified': obj.get('modified', 'Unknown')
                })
        print(f"[+] Found {len(self.groups)} groups")
        return pd.DataFrame(self.groups)

    def get_group_techniques(self, group_name):
        """Get TTPs for specific threat actor"""
        group_id = None
        for g in self.groups:
            if g['name'].lower() == group_name.lower() or \
               group_name.lower() in [a.lower() for a in g['aliases']]:
                group_id = g['id']
                break
        if not group_id:
            return pd.DataFrame()
        techniques = []
        for obj in self.data['objects']:
            if obj['type'] == 'relationship' and \
               obj.get('source_ref') == group_id and \
               obj.get('relationship_type') == 'uses':
                target_id = obj['target_ref']
                for tech in self.data['objects']:
                    if tech['id'] == target_id and tech['type'] == 'attack-pattern':
                        techniques.append({
                            'technique_id': tech.get('external_references', [{}])[0].get('external_id', 'Unknown'),
                            'technique_name': tech['name'],
                            'tactic': ', '.join([p['phase_name'] for p in tech.get('kill_chain_phases', [])])
                        })
        return pd.DataFrame(techniques)

    def build_ttp_matrix(self):
        """Build binary feature matrix: groups x techniques"""
        print("[*] Building TTP matrix...")
        all_techniques = set()
        group_ttp_map = {}
        for group in self.groups:
            name = group['name']
            techs = self.get_group_techniques(name)
            if not techs.empty:
                tech_ids = set(techs['technique_id'].values)
                group_ttp_map[name] = tech_ids
                all_techniques.update(tech_ids)
        technique_list = sorted(list(all_techniques))
        matrix_data, group_names = [], []
        for name, techs in group_ttp_map.items():
            row = [1 if t in techs else 0 for t in technique_list]
            matrix_data.append(row)
            group_names.append(name)
        self.ttp_matrix = pd.DataFrame(matrix_data, columns=technique_list, index=group_names)
        print(f"[+] Matrix: {len(group_names)} groups x {len(technique_list)} techniques")
        return self.ttp_matrix

    def calculate_similarity(self):
        """Compute cosine similarity between all groups"""
        if self.ttp_matrix is None:
            self.build_ttp_matrix()
        print("[*] Calculating similarity scores...")
        similarity = cosine_similarity(self.ttp_matrix)
        self.similarity_matrix = pd.DataFrame(
            similarity, index=self.ttp_matrix.index, columns=self.ttp_matrix.index
        )
        return self.similarity_matrix

    def find_similar_groups(self, group_name, top_n=5):
        """Find most similar threat actors"""
        if self.similarity_matrix is None:
            self.calculate_similarity()
        if group_name not in self.similarity_matrix.index:
            print(f"[!] Group '{group_name}' not found")
            return pd.DataFrame()
        similar = self.similarity_matrix[group_name].sort_values(ascending=False)[1:top_n+1]
        print(f"\nTop {top_n} groups similar to {group_name}:")
        for g, score in similar.items():
            print(f"  {g}: {score:.3f}")
        return similar

    def cluster_threat_actors(self, n_clusters=5):
        """K-Means clustering of threat actors"""
        if self.ttp_matrix is None:
            self.build_ttp_matrix()
        print(f"[*] Clustering into {n_clusters} groups...")
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        labels = kmeans.fit_predict(self.ttp_matrix)
        results = pd.DataFrame({
            'group': self.ttp_matrix.index,
            'cluster': labels,
            'num_techniques': self.ttp_matrix.sum(axis=1).values
        })
        print(f"[+] Cluster distribution:\n{results['cluster'].value_counts().sort_index()}")
        return results

    def plot_threat_landscape(self, n_clusters=5):
        """PCA visualization of threat actor landscape"""
        if self.ttp_matrix is None:
            self.build_ttp_matrix()
        pca = PCA(n_components=2, random_state=42)
        coords = pca.fit_transform(self.ttp_matrix)
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        clusters = kmeans.fit_predict(self.ttp_matrix)
        fig, ax = plt.subplots(figsize=(14, 10))
        scatter = ax.scatter(coords[:, 0], coords[:, 1], c=clusters, cmap='tab10',
                            s=100, alpha=0.6, edgecolors='black')
        for i, group in enumerate(self.ttp_matrix.index):
            ax.annotate(group, (coords[i, 0], coords[i, 1]),
                       fontsize=7, xytext=(5, 5), textcoords='offset points')
        ax.set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.1%})', fontweight='bold')
        ax.set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.1%})', fontweight='bold')
        ax.set_title('Threat Actor Landscape - TTP Clustering', fontweight='bold', fontsize=14)
        ax.grid(alpha=0.3)
        plt.colorbar(scatter, label='Cluster')
        plt.tight_layout()
        plt.show()

    def plot_similarity_heatmap(self, top_n=20):
        """Heatmap of threat actor similarity"""
        if self.similarity_matrix is None:
            self.calculate_similarity()
        top_groups = self.ttp_matrix.sum(axis=1).nlargest(top_n).index
        subset = self.similarity_matrix.loc[top_groups, top_groups]
        fig, ax = plt.subplots(figsize=(12, 10))
        sns.heatmap(subset, cmap='RdYlGn', vmin=0, vmax=1, square=True,
                   cbar_kws={'label': 'Similarity'})
        ax.set_title(f'Threat Actor Similarity Matrix (Top {top_n})', fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()

    def plot_dendrogram(self, top_n=25):
        """Hierarchical clustering dendrogram"""
        if self.ttp_matrix is None:
            self.build_ttp_matrix()
        top_groups = self.ttp_matrix.sum(axis=1).nlargest(top_n).index
        subset = self.ttp_matrix.loc[top_groups]
        linkage_matrix = linkage(subset, method='ward')
        fig, ax = plt.subplots(figsize=(14, 8))
        dendrogram(linkage_matrix, labels=subset.index, leaf_rotation=90, leaf_font_size=9)
        ax.set_title(f'Threat Actor Hierarchy (Top {top_n})', fontweight='bold')
        ax.set_ylabel('Distance', fontweight='bold')
        plt.tight_layout()
        plt.show()

    def plot_ttp_distribution(self, group_name):
        """Bar chart of TTP distribution by tactic"""
        techs = self.get_group_techniques(group_name)
        if techs.empty:
            print(f"[!] No data for {group_name}")
            return
        tactic_counts = {}
        for tactics in techs['tactic']:
            for tactic in tactics.split(', '):
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        fig, ax = plt.subplots(figsize=(10, 6))
        tactics = list(tactic_counts.keys())
        counts = list(tactic_counts.values())
        bars = ax.barh(tactics, counts, color='crimson')
        ax.set_xlabel('Techniques', fontweight='bold')
        ax.set_title(f'{group_name} - TTP Distribution', fontweight='bold')
        ax.grid(axis='x', alpha=0.3)
        for bar in bars:
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2,
                   f' {int(width)}', ha='left', va='center', fontweight='bold')
        plt.tight_layout()
        plt.show()

    def generate_profile(self, group_name):
        """Complete threat intelligence profile"""
        print(f"\n{'='*60}")
        print(f"THREAT ACTOR PROFILE: {group_name.upper()}")
        print(f"{'='*60}\n")
        group_data = None
        for g in self.groups:
            if g['name'].lower() == group_name.lower() or \
               group_name.lower() in [a.lower() for a in g['aliases']]:
                group_data = g
                break
        if not group_data:
            print(f"[!] Group not found")
            return None
        print(f"NAME: {group_data['name']}")
        print(f"ALIASES: {', '.join(group_data['aliases'])}")
        print(f"OBSERVED: {group_data['created'][:10]}")
        print(f"UPDATED: {group_data['modified'][:10]}")
        print(f"\n{group_data['description'][:400]}...\n")
        techs = self.get_group_techniques(group_name)
        if not techs.empty:
            print(f"TECHNIQUES: {len(techs)} identified\n")
            print(techs[['technique_id', 'technique_name']].head(10).to_string(index=False))
            if len(techs) > 10:
                print(f"\n... +{len(techs)-10} more")
        print(f"\n{'='*60}")
        print("SIMILAR GROUPS (ML Analysis)")
        print(f"{'='*60}\n")
        similar = self.find_similar_groups(group_name, top_n=5)
        print(f"\n{'='*60}")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"{'='*60}\n")
        return {'group': group_data, 'techniques': techs, 'similar': similar}

    def export_data(self, prefix='threat_analysis', include_metadata=True):
        """Enhanced export with timestamps, metadata, and summary statistics"""
        import os
        import json
        output_dir = os.path.dirname(prefix) if os.path.dirname(prefix) else 'outputs'
        os.makedirs(f'{output_dir}/raw', exist_ok=True)
        os.makedirs(f'{output_dir}/processed', exist_ok=True)
        os.makedirs(f'{output_dir}/summaries', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = os.path.basename(prefix)
        print(f"[*] Exporting analysis data with timestamp: {timestamp}")
        print("="*60)
        if self.ttp_matrix is not None:
            fp = f'{output_dir}/raw/{base_name}_ttp_matrix_{timestamp}.csv'
            self.ttp_matrix.to_csv(fp)
            print(f"[+] TTP Matrix: {fp}")
        if self.similarity_matrix is not None:
            fp = f'{output_dir}/processed/{base_name}_similarity_{timestamp}.csv'
            self.similarity_matrix.round(3).to_csv(fp)
            print(f"[+] Similarity Matrix: {fp}")
        groups_df = pd.DataFrame(self.groups)
        if self.ttp_matrix is not None:
            groups_df['technique_count'] = groups_df['name'].apply(
                lambda x: len(self.get_group_techniques(x)) if x in self.ttp_matrix.index else 0
            )
        groups_df['malware_count'] = groups_df['name'].apply(lambda x: len(self.get_group_malware(x)))
        groups_df['tool_count'] = groups_df['name'].apply(lambda x: len(self.get_group_tools(x)))
        groups_df['total_arsenal'] = groups_df['malware_count'] + groups_df['tool_count']
        fp = f'{output_dir}/processed/{base_name}_groups_enhanced_{timestamp}.csv'
        groups_df.to_csv(fp, index=False)
        print(f"[+] Enhanced Groups DB: {fp}")
        summary_stats = {
            'metric': ['Total Groups Analyzed', 'Total Techniques Tracked',
                      'Average Techniques per Group', 'Most Techniques (Group)',
                      'Most Techniques (Count)', 'Total Malware Families',
                      'Total Tools', 'Export Timestamp', 'MITRE Source'],
            'value': [
                len(self.groups),
                self.ttp_matrix.shape[1] if self.ttp_matrix is not None else 0,
                f"{self.ttp_matrix.sum(axis=1).mean():.1f}" if self.ttp_matrix is not None else 0,
                self.ttp_matrix.sum(axis=1).idxmax() if self.ttp_matrix is not None else 'N/A',
                int(self.ttp_matrix.sum(axis=1).max()) if self.ttp_matrix is not None else 0,
                len(self.extract_all_malware()),
                len(self.extract_all_tools()),
                datetime.now().isoformat(),
                self.mitre_url
            ]
        }
        fp = f'{output_dir}/summaries/{base_name}_summary_{timestamp}.csv'
        pd.DataFrame(summary_stats).to_csv(fp, index=False)
        print(f"[+] Summary Statistics: {fp}")
        if include_metadata:
            metadata = {
                'export_timestamp': datetime.now().isoformat(),
                'total_groups': len(self.groups),
                'groups_with_ttps': self.ttp_matrix.shape[0] if self.ttp_matrix is not None else 0,
                'total_techniques': self.ttp_matrix.shape[1] if self.ttp_matrix is not None else 0,
                'mitre_source_url': self.mitre_url,
                'analysis_version': 'Phase 4 - Predictive Attribution',
                'export_prefix': prefix
            }
            fp = f'{output_dir}/metadata_{timestamp}.json'
            with open(fp, 'w') as f:
                json.dump(metadata, f, indent=2)
            print(f"[+] Metadata: {fp}")
        data_dict = f"""THREAT ACTOR PROFILER - DATA EXPORT DICTIONARY
Generated: {timestamp}

FILE DESCRIPTIONS:
1. ttp_matrix_[timestamp].csv - Binary feature matrix
2. similarity_[timestamp].csv - Cosine similarity scores (rounded to 3 decimals)
3. groups_enhanced_[timestamp].csv - Complete database with computed metrics
4. summary_[timestamp].csv - Key statistics
5. metadata_[timestamp].json - Export parameters

DIRECTORY STRUCTURE:
- raw/: Unprocessed data
- processed/: Cleaned data
- summaries/: Aggregated statistics
"""
        with open(f'{output_dir}/DATA_DICTIONARY.txt', 'w') as f:
            f.write(data_dict)
        print(f"[+] Data Dictionary: {output_dir}/DATA_DICTIONARY.txt")
        print("\n" + "="*60)
        print(f"[+] Export complete - {6 if include_metadata else 5} files generated")
        print("="*60)

    def extract_all_malware(self):
        """Extract all malware families from MITRE dataset"""
        print("[*] Extracting malware families...")
        malware_list = []
        for obj in self.data['objects']:
            if obj['type'] == 'malware':
                malware_list.append({
                    'id': obj['id'],
                    'name': obj['name'],
                    'aliases': obj.get('x_mitre_aliases', []),
                    'description': obj.get('description', 'No description'),
                    'platforms': obj.get('x_mitre_platforms', [])
                })
        print(f"[+] Found {len(malware_list)} malware families")
        return malware_list

    def extract_all_tools(self):
        """Extract all tools/software from MITRE dataset"""
        print("[*] Extracting tools and software...")
        tool_list = []
        for obj in self.data['objects']:
            if obj['type'] == 'tool':
                tool_list.append({
                    'id': obj['id'],
                    'name': obj['name'],
                    'aliases': obj.get('x_mitre_aliases', []),
                    'description': obj.get('description', 'No description'),
                    'platforms': obj.get('x_mitre_platforms', [])
                })
        print(f"[+] Found {len(tool_list)} tools")
        return tool_list

    def get_group_malware(self, group_name):
        """Get malware families used by specific threat actor"""
        group_id = None
        for g in self.groups:
            if g['name'].lower() == group_name.lower() or \
               group_name.lower() in [a.lower() for a in g['aliases']]:
                group_id = g['id']
                break
        if not group_id:
            return pd.DataFrame()
        malware_used = []
        for obj in self.data['objects']:
            if obj['type'] == 'relationship' and \
               obj.get('source_ref') == group_id and \
               obj.get('relationship_type') == 'uses':
                target_id = obj['target_ref']
                for malware_obj in self.data['objects']:
                    if malware_obj['id'] == target_id and malware_obj['type'] == 'malware':
                        malware_used.append({
                            'malware_name': malware_obj['name'],
                            'type': 'Malware',
                            'description': malware_obj.get('description', 'No description')[:150],
                            'platforms': ', '.join(malware_obj.get('x_mitre_platforms', []))
                        })
        return pd.DataFrame(malware_used)

    def get_group_tools(self, group_name):
        """Get tools/software used by specific threat actor"""
        group_id = None
        for g in self.groups:
            if g['name'].lower() == group_name.lower() or \
               group_name.lower() in [a.lower() for a in g['aliases']]:
                group_id = g['id']
                break
        if not group_id:
            return pd.DataFrame()
        tools_used = []
        for obj in self.data['objects']:
            if obj['type'] == 'relationship' and \
               obj.get('source_ref') == group_id and \
               obj.get('relationship_type') == 'uses':
                target_id = obj['target_ref']
                for tool_obj in self.data['objects']:
                    if tool_obj['id'] == target_id and tool_obj['type'] == 'tool':
                        tools_used.append({
                            'tool_name': tool_obj['name'],
                            'type': 'Tool',
                            'description': tool_obj.get('description', 'No description')[:150],
                            'platforms': ', '.join(tool_obj.get('x_mitre_platforms', []))
                        })
        return pd.DataFrame(tools_used)

    def get_group_arsenal(self, group_name, silent=False):
        """Get complete arsenal: malware + tools used by threat actor"""
        malware_df = self.get_group_malware(group_name)
        tools_df = self.get_group_tools(group_name)
        arsenal = pd.concat([malware_df, tools_df], ignore_index=True)
        if not arsenal.empty and not silent:
            print(f"\n{group_name} Arsenal Summary:")
            print(f"  Custom Malware: {len(malware_df)}")
            print(f"  Tools/Software: {len(tools_df)}")
            print(f"  Total Arsenal: {len(arsenal)}")
        return arsenal

    def compare_group_arsenals(self, group_list):
        """Compare arsenals across multiple threat actors"""
        comparison = {}
        for group in group_list:
            arsenal = self.get_group_arsenal(group, silent=True)
            comparison[group] = {
                'total': len(arsenal),
                'malware': len(self.get_group_malware(group)),
                'tools': len(self.get_group_tools(group))
            }
        return pd.DataFrame(comparison).T

    def find_shared_malware(self, malware_name):
        """Find which threat actors use specific malware/tool"""
        print(f"[*] Finding groups that use {malware_name}...")
        using_groups = []
        for group in self.groups:
            arsenal = self.get_group_arsenal(group['name'], silent=True)
            if not arsenal.empty:
                found = False
                if 'malware_name' in arsenal.columns:
                    if arsenal['malware_name'].str.contains(malware_name, case=False, na=False).any():
                        found = True
                if 'tool_name' in arsenal.columns:
                    if arsenal['tool_name'].str.contains(malware_name, case=False, na=False).any():
                        found = True
                if found:
                    using_groups.append(group['name'])
        print(f"[+] {len(using_groups)} groups use {malware_name}")
        return using_groups

    def generate_enhanced_profile(self, group_name):
        """Generate enhanced profile with arsenal analysis"""
        base_profile = self.generate_profile(group_name)
        if not base_profile:
            return None
        print(f"\n{'='*60}")
        print("OPERATIONAL ARSENAL ANALYSIS")
        print(f"{'='*60}\n")
        arsenal = self.get_group_arsenal(group_name, silent=True)
        if not arsenal.empty:
            malware = arsenal[arsenal['type'] == 'Malware']
            tools = arsenal[arsenal['type'] == 'Tool']
            if not malware.empty:
                print(f"CUSTOM MALWARE ({len(malware)} families):\n")
                for idx, row in malware.head(10).iterrows():
                    print(f"  • {row['malware_name']}")
                    print(f"    {row['description']}...\n")
                if len(malware) > 10:
                    print(f"  ... and {len(malware) - 10} more malware families\n")
            if not tools.empty:
                print(f"\nTOOLS & SOFTWARE ({len(tools)} items):\n")
                for idx, row in tools.head(10).iterrows():
                    print(f"  • {row['tool_name']}")
                    print(f"    {row['description']}...\n")
                if len(tools) > 10:
                    print(f"  ... and {len(tools) - 10} more tools\n")
        else:
            print(f"No documented malware or tools for {group_name} in MITRE database")
        print(f"{'='*60}")
        print(f"ENHANCED PROFILE COMPLETE")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"{'='*60}\n")
        return {
            'group': base_profile['group'],
            'techniques': base_profile['techniques'],
            'similar': base_profile['similar'],
            'arsenal': arsenal
        }

    def plot_arsenal_comparison(self, group_list):
        """Visualize arsenal comparison across threat actors"""
        comparison = self.compare_group_arsenals(group_list)
        fig, ax = plt.subplots(figsize=(12, 6))
        x = np.arange(len(group_list))
        width = 0.35
        malware_counts = [comparison.loc[g, 'malware'] for g in group_list]
        tool_counts = [comparison.loc[g, 'tools'] for g in group_list]
        ax.bar(x - width/2, malware_counts, width, label='Custom Malware', color='crimson')
        ax.bar(x + width/2, tool_counts, width, label='Tools/Software', color='steelblue')
        ax.set_xlabel('Threat Actor Group', fontweight='bold')
        ax.set_ylabel('Count', fontweight='bold')
        ax.set_title('Threat Actor Arsenal Comparison\nMalware vs Tools', fontweight='bold', fontsize=14)
        ax.set_xticks(x)
        ax.set_xticklabels(group_list, rotation=45, ha='right')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.show()

    # ========================================
    # PHASE 4: SECTOR TARGETING ANALYSIS
    # ========================================

    def extract_sector_targeting(self):
        """Extract victim sector targeting data from MITRE descriptions"""
        print("[*] Extracting sector targeting data...")
        sector_keywords = {
            'Government': ['government', 'ministry', 'federal', 'state agency', 'public sector', 'military', 'defense'],
            'Energy': ['energy', 'oil', 'gas', 'utilities', 'power grid', 'nuclear', 'petrochemical'],
            'Finance': ['financial', 'banking', 'bank', 'cryptocurrency', 'fintech', 'swift', 'atm'],
            'Healthcare': ['healthcare', 'hospital', 'pharmaceutical', 'medical', 'biotech', 'health'],
            'Technology': ['technology', 'software', 'telecom', 'telecommunications', 'it sector', 'tech'],
            'Defense': ['defense contractor', 'aerospace', 'arms', 'weapons', 'military contractor'],
            'Manufacturing': ['manufacturing', 'industrial', 'factory', 'supply chain', 'automotive'],
            'Education': ['university', 'academic', 'research institution', 'think tank', 'education'],
            'Media': ['media', 'journalism', 'news', 'broadcasting', 'entertainment'],
            'NGO': ['ngo', 'non-governmental', 'nonprofit', 'human rights', 'civil society']
        }
        sector_data = []
        for group in self.groups:
            desc = group.get('description', '').lower()
            targeted_sectors = [s for s, kws in sector_keywords.items() if any(kw in desc for kw in kws)]
            sector_data.append({
                'group': group['name'],
                'sectors': targeted_sectors,
                'sector_count': len(targeted_sectors)
            })
        df = pd.DataFrame(sector_data)
        print(f"[+] Sector targeting extracted for {len(df)} groups")
        return df

    def get_group_sectors(self, group_name):
        """Get targeted sectors for a specific threat actor"""
        sector_df = self.extract_sector_targeting()
        row = sector_df[sector_df['group'] == group_name]
        return [] if row.empty else row.iloc[0]['sectors']

    def get_sector_threat_actors(self, sector):
        """Get all threat actors targeting a specific sector"""
        sector_df = self.extract_sector_targeting()
        return sector_df[sector_df['sectors'].apply(lambda s: sector in s)]['group'].tolist()

    def plot_sector_targeting_heatmap(self, top_n=20):
        """Heatmap showing which threat actors target which sectors"""
        sector_df = self.extract_sector_targeting()
        active = sector_df[sector_df['sector_count'] > 0].nlargest(top_n, 'sector_count')
        sectors = ['Government', 'Energy', 'Finance', 'Healthcare', 'Technology',
                   'Defense', 'Manufacturing', 'Education', 'Media', 'NGO']
        matrix = pd.DataFrame(0, index=active['group'], columns=sectors)
        for _, row in active.iterrows():
            for sector in row['sectors']:
                if sector in matrix.columns:
                    matrix.loc[row['group'], sector] = 1
        fig, ax = plt.subplots(figsize=(14, 10))
        sns.heatmap(matrix, cmap='YlOrRd', linewidths=0.5, linecolor='#1a1a2e',
                   cbar_kws={'label': 'Targets Sector'}, ax=ax)
        ax.set_title(f'Sector Targeting Heatmap (Top {top_n} Groups)', fontweight='bold', fontsize=14)
        ax.set_xlabel('Industry Sector', fontweight='bold')
        ax.set_ylabel('Threat Actor', fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.show()

    def plot_sector_distribution(self):
        """Bar chart showing which sectors are most targeted across all groups"""
        sector_df = self.extract_sector_targeting()
        sector_counts = {}
        for sectors in sector_df['sectors']:
            for s in sectors:
                sector_counts[s] = sector_counts.get(s, 0) + 1
        if not sector_counts:
            print("[!] No sector data found")
            return
        sorted_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)
        labels = [s[0] for s in sorted_sectors]
        counts = [s[1] for s in sorted_sectors]
        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.bar(labels, counts, color='steelblue', edgecolor='black')
        ax.set_xlabel('Industry Sector', fontweight='bold')
        ax.set_ylabel('Number of Threat Actors', fontweight='bold')
        ax.set_title('Most Targeted Sectors Across All APT Groups', fontweight='bold', fontsize=14)
        plt.xticks(rotation=45, ha='right')
        ax.grid(axis='y', alpha=0.3)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., h + 0.3,
                   f'{int(h)}', ha='center', va='bottom', fontweight='bold')
        plt.tight_layout()
        plt.show()

    def nation_state_sector_analysis(self):
        """Cross-reference nation-state attribution with sector targeting"""
        nation_keywords = {
            'Russia': ['APT28', 'APT29', 'Turla', 'Sandworm Team', 'Gamaredon Group', 'Forest Blizzard', 'UNC2452', 'Ember Bear'],
            'China': ['APT1', 'APT3', 'APT10', 'APT41', 'Mustang Panda', 'menuPass', 'HAFNIUM', 'GALLIUM', 'Volt Typhoon', 'Threat Group-3390', 'Earth Lusca', 'Tonto Team'],
            'North Korea': ['Lazarus Group', 'APT38', 'Kimsuky', 'Andariel', 'APT37', 'Contagious Interview', 'Diamond Sleet'],
            'Iran': ['APT33', 'APT34', 'OilRig', 'MuddyWater', 'Charming Kitten', 'Magic Hound', 'APT39', 'Fox Kitten', 'Agrius']
        }
        sector_df = self.extract_sector_targeting()
        results = {}
        for nation, groups in nation_keywords.items():
            nation_sectors = {}
            for group in groups:
                row = sector_df[sector_df['group'] == group]
                if not row.empty:
                    for sector in row.iloc[0]['sectors']:
                        nation_sectors[sector] = nation_sectors.get(sector, 0) + 1
            results[nation] = nation_sectors
        print("\nNATION-STATE SECTOR TARGETING ANALYSIS")
        print("="*60)
        for nation, sectors in results.items():
            if sectors:
                top = sorted(sectors.items(), key=lambda x: x[1], reverse=True)
                print(f"\n{nation}:")
                for sector, count in top:
                    print(f"  {sector}: {count} group(s)")
        return results

    # ========================================
    # PHASE 4: NETWORK GRAPH VISUALIZATION
    # ========================================

    def build_malware_network(self, min_shared=2):
        """Build a network graph connecting threat actors via shared malware/tools"""
        try:
            import networkx as nx
        except ImportError:
            print("[!] networkx not installed. Run: pip install networkx")
            return None
        print(f"[*] Building malware sharing network (min_shared={min_shared})...")
        group_arsenals = {}
        for group in self.groups:
            arsenal = self.get_group_arsenal(group['name'], silent=True)
            if not arsenal.empty:
                items = set()
                if 'malware_name' in arsenal.columns:
                    items.update(arsenal['malware_name'].dropna().tolist())
                if 'tool_name' in arsenal.columns:
                    items.update(arsenal['tool_name'].dropna().tolist())
                if items:
                    group_arsenals[group['name']] = items
        G = nx.Graph()
        for group in group_arsenals:
            G.add_node(group, techniques=len(self.get_group_techniques(group)))
        group_list = list(group_arsenals.keys())
        for i in range(len(group_list)):
            for j in range(i + 1, len(group_list)):
                g1, g2 = group_list[i], group_list[j]
                shared = group_arsenals[g1] & group_arsenals[g2]
                if len(shared) >= min_shared:
                    G.add_edge(g1, g2, weight=len(shared), shared_tools=list(shared))
        print(f"[+] Network: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        return G

    def plot_malware_network(self, min_shared=2, top_n=40):
        """Visualize the threat actor network graph based on shared malware/tools"""
        try:
            import networkx as nx
        except ImportError:
            print("[!] networkx not installed. Run: pip install networkx")
            return
        G = self.build_malware_network(min_shared=min_shared)
        if G is None or G.number_of_nodes() == 0:
            print("[!] No network data to plot")
            return
        degrees = dict(G.degree())
        top_nodes = sorted(degrees, key=degrees.get, reverse=True)[:top_n]
        G = G.subgraph(top_nodes).copy()
        fig, ax = plt.subplots(figsize=(16, 12))
        ax.set_facecolor('#0a1929')
        fig.patch.set_facecolor('#0a1929')
        pos = nx.spring_layout(G, k=2, seed=42)
        node_sizes = [G.nodes[n].get('techniques', 10) * 8 + 100 for n in G.nodes()]
        edge_weights = [G[u][v]['weight'] for u, v in G.edges()]
        max_w = max(edge_weights) if edge_weights else 1
        edge_widths = [1 + (w / max_w) * 4 for w in edge_weights]
        nx.draw_networkx_edges(G, pos, ax=ax, width=edge_widths, alpha=0.4, edge_color='#00d4ff')
        nx.draw_networkx_nodes(G, pos, ax=ax, node_size=node_sizes, node_color='#0ea5e9',
                              alpha=0.85, edgecolors='#00d4ff', linewidths=1.5)
        nx.draw_networkx_labels(G, pos, ax=ax, font_size=7, font_color='white', font_weight='bold')
        ax.set_title(
            f'Threat Actor Infrastructure Sharing Network\n'
            f'(Edges = ≥{min_shared} shared malware/tools | Node size = technique count)',
            color='#00d4ff', fontweight='bold', fontsize=13
        )
        ax.axis('off')
        plt.tight_layout()
        plt.show()

    # ========================================
    # PHASE 4: PREDICTIVE ATTRIBUTION MODEL
    # ========================================

    def train_attribution_model(self):
        """
        Train a Random Forest classifier to predict nation-state sponsor
        from a set of observed TTPs.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
        from sklearn.metrics import accuracy_score, classification_report

        if self.ttp_matrix is None:
            self.build_ttp_matrix()

        print("[*] Training nation-state attribution classifier...")

        nation_labels = {
            'Russia': ['APT28', 'APT29', 'Turla', 'Sandworm Team', 'Gamaredon Group',
                      'Forest Blizzard', 'UNC2452', 'Ember Bear'],
            'China': ['APT1', 'APT3', 'APT10', 'APT41', 'APT19', 'APT18', 'APT17',
                     'Mustang Panda', 'menuPass', 'HAFNIUM', 'GALLIUM', 'Volt Typhoon',
                     'Threat Group-3390', 'Earth Lusca', 'Tonto Team', 'Daggerfly'],
            'North Korea': ['Lazarus Group', 'APT38', 'Kimsuky', 'Andariel', 'APT37',
                           'Contagious Interview', 'Diamond Sleet'],
            'Iran': ['APT33', 'APT34', 'OilRig', 'MuddyWater', 'Charming Kitten',
                    'Magic Hound', 'APT39', 'Fox Kitten', 'Agrius']
        }

        X_list, y_list = [], []
        for nation, groups in nation_labels.items():
            for group in groups:
                if group in self.ttp_matrix.index:
                    X_list.append(self.ttp_matrix.loc[group].values)
                    y_list.append(nation)

        if len(X_list) < 10:
            print("[!] Not enough labeled data to train")
            return None, None, 0.0

        X = np.array(X_list)
        le = LabelEncoder()
        y = le.fit_transform(y_list)

        print(f"[+] Training samples: {len(X_list)}")
        print(f"[+] Nation-state classes: {list(le.classes_)}")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        clf = RandomForestClassifier(
            n_estimators=200, max_depth=None, random_state=42,
            class_weight='balanced', n_jobs=-1
        )
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)

        print(f"[+] Test accuracy: {acc:.2%}")
        print(f"\n[+] Classification Report:")
        print(classification_report(y_test, y_pred, labels=np.unique(y_test), target_names=le.classes_[np.unique(y_test)]))

        return clf, le, acc

    def predict_threat_actor(self, observed_techniques):
        """
        Given a list of observed technique IDs, predict the most likely
        nation-state sponsor using the trained classifier.
        """
        if self.ttp_matrix is None:
            self.build_ttp_matrix()

        clf, le, acc = self.train_attribution_model()
        if clf is None:
            return pd.DataFrame()

        input_vector = np.zeros(len(self.ttp_matrix.columns))
        matched = 0
        for i, tech_id in enumerate(self.ttp_matrix.columns):
            if tech_id in observed_techniques:
                input_vector[i] = 1
                matched += 1

        print(f"\n[*] Nation-State Attribution Analysis")
        print(f"    Observed techniques: {len(observed_techniques)}")
        print(f"    Matched in database: {matched}")

        proba = clf.predict_proba(input_vector.reshape(1, -1))[0]

        print(f"\n{'='*60}")
        print("NATION-STATE ATTRIBUTION RESULTS")
        print(f"{'='*60}\n")

        results = []
        for idx, nation in enumerate(le.classes_):
            confidence = proba[idx]
            level = 'High' if confidence > 0.5 else 'Moderate' if confidence > 0.25 else 'Low'
            print(f"  {nation:<15}: {confidence:.1%} confidence ({level})")
            results.append({'nation_state': nation, 'confidence': confidence, 'confidence_level': level})

        results = sorted(results, key=lambda x: x['confidence'], reverse=True)

        print(f"\n[+] Model accuracy: {acc:.2%}")
        print(f"{'='*60}\n")

        return pd.DataFrame(results)

    def plot_feature_importance(self, top_n=20):
        """Plot the most important techniques for nation-state attribution"""
        clf, le, acc = self.train_attribution_model()
        if clf is None:
            return

        importances = clf.feature_importances_
        tech_names = self.ttp_matrix.columns
        top_idx = np.argsort(importances)[::-1][:top_n]
        top_techs = [tech_names[i] for i in top_idx]
        top_imp = [importances[i] for i in top_idx]

        fig, ax = plt.subplots(figsize=(12, 8))
        bars = ax.barh(range(top_n), top_imp[::-1], color='#0ea5e9', edgecolor='black')
        ax.set_yticks(range(top_n))
        ax.set_yticklabels(top_techs[::-1], fontsize=9)
        ax.set_xlabel('Feature Importance', fontweight='bold')
        ax.set_title(f'Top {top_n} Most Diagnostic Techniques for Nation-State Attribution\n(Random Forest Feature Importance)',
                    fontweight='bold', fontsize=13)
        ax.grid(axis='x', alpha=0.3)
        for bar in bars:
            w = bar.get_width()
            ax.text(w + 0.0005, bar.get_y() + bar.get_height()/2,
                   f'{w:.4f}', ha='left', va='center', fontsize=8)
        plt.tight_layout()
        plt.show()


if __name__ == "__main__":
    print("ThreatActorProfiler module loaded\n")
    profiler = ThreatActorProfiler()
    if profiler.fetch_mitre_data():
        profiler.extract_threat_groups()
        print("Ready for analysis!")