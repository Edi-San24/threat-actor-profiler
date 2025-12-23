"""
Threat Actor Profile Aggregator
Author: Edi
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
        # Find group ID
        group_id = None
        for g in self.groups:
            if g['name'].lower() == group_name.lower() or \
               group_name.lower() in [a.lower() for a in g['aliases']]:
                group_id = g['id']
                break
        
        if not group_id:
            return pd.DataFrame()
        
        # Extract techniques
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
        
        # Map groups to their techniques
        all_techniques = set()
        group_ttp_map = {}
        
        for group in self.groups:
            name = group['name']
            techs = self.get_group_techniques(name)
            if not techs.empty:
                tech_ids = set(techs['technique_id'].values)
                group_ttp_map[name] = tech_ids
                all_techniques.update(tech_ids)
        
        # Build binary matrix
        technique_list = sorted(list(all_techniques))
        matrix_data = []
        group_names = []
        
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
            similarity,
            index=self.ttp_matrix.index,
            columns=self.ttp_matrix.index
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
        
        # Reduce to 2D
        pca = PCA(n_components=2, random_state=42)
        coords = pca.fit_transform(self.ttp_matrix)
        
        # Cluster for colors
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        clusters = kmeans.fit_predict(self.ttp_matrix)
        
        # Plot
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
        
        # Find group
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
        
        # TTPs
        techs = self.get_group_techniques(group_name)
        if not techs.empty:
            print(f"TECHNIQUES: {len(techs)} identified\n")
            print(techs[['technique_id', 'technique_name']].head(10).to_string(index=False))
            if len(techs) > 10:
                print(f"\n... +{len(techs)-10} more")
        
        # Similarity
        print(f"\n{'='*60}")
        print("SIMILAR GROUPS (ML Analysis)")
        print(f"{'='*60}\n")
        similar = self.find_similar_groups(group_name, top_n=5)
        
        print(f"\n{'='*60}")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"{'='*60}\n")
        
        return {'group': group_data, 'techniques': techs, 'similar': similar}
    
    def export_data(self, prefix='threat_analysis'):
        """Export to CSV"""
        if self.ttp_matrix is not None:
            self.ttp_matrix.to_csv(f'{prefix}_matrix.csv')
        if self.similarity_matrix is not None:
            self.similarity_matrix.to_csv(f'{prefix}_similarity.csv')
        pd.DataFrame(self.groups).to_csv(f'{prefix}_groups.csv', index=False)
        print(f"[+] Exported data with prefix: {prefix}")


if __name__ == "__main__":
    print("ThreatActorProfiler module loaded\n")
    profiler = ThreatActorProfiler()
    if profiler.fetch_mitre_data():
        profiler.extract_threat_groups()
        print("Ready for analysis!")