"""
Comprehensive Network Traffic Visualization Dashboard
Creates interactive visualizations for network security analysis
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import warnings
from typing import Dict, List, Tuple, Optional, Any
import os

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.offline as pyo
    PLOTLY_AVAILABLE = True
except ImportError:
    print("Warning: Plotly not available. Install with: pip install plotly")
    PLOTLY_AVAILABLE = False

try:
    import folium
    from folium import plugins
    FOLIUM_AVAILABLE = True
except ImportError:
    print("Warning: Folium not available. Install with: pip install folium")
    FOLIUM_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    print("Warning: NetworkX not available. Install with: pip install networkx")
    NETWORKX_AVAILABLE = False

warnings.filterwarnings('ignore')

class NetworkTrafficVisualizer:
    """Comprehensive network traffic visualization system"""
    
    def __init__(self, figsize=(12, 8), theme='plotly_dark'):
        """
        Initialize the visualizer
        
        Args:
            figsize: Default figure size for matplotlib plots
            theme: Plotly theme ('plotly_dark', 'plotly_white', etc.)
        """
        self.figsize = figsize
        self.theme = theme
        self.colors = {
            'normal': '#2E8B57',
            'anomaly': '#DC143C',
            'suspicious': '#FF8C00',
            'primary': '#1f77b4',
            'secondary': '#ff7f0e'
        }
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        if PLOTLY_AVAILABLE:
            pyo.init_notebook_mode(connected=True)
    
    def plot_traffic_overview(self, df: pd.DataFrame, save_path: Optional[str] = None) -> go.Figure:
        """
        Create comprehensive traffic overview dashboard
        
        Args:
            df: Network traffic DataFrame
            save_path: Optional path to save the plot
            
        Returns:
            Plotly figure object
        """
        if not PLOTLY_AVAILABLE:
            print("Plotly not available for interactive plots")
            return None
            
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Traffic Volume Over Time', 'Protocol Distribution', 
                          'Packet Size Distribution', 'Top Source IPs'],
            specs=[[{"secondary_y": False}, {"type": "pie"}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        # Convert timestamp if needed
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        elif 'datetime' in df.columns:
            df['datetime'] = pd.to_datetime(df['datetime'])
        
        # Traffic volume over time
        if 'datetime' in df.columns:
            traffic_over_time = df.groupby(df['datetime'].dt.floor('H')).size()
            fig.add_trace(
                go.Scatter(x=traffic_over_time.index, y=traffic_over_time.values,
                          mode='lines+markers', name='Packets/Hour'),
                row=1, col=1
            )
        
        # Protocol distribution
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            fig.add_trace(
                go.Pie(labels=protocol_counts.index, values=protocol_counts.values,
                      name="Protocol Distribution"),
                row=1, col=2
            )
        
        # Packet size distribution
        if 'packet_size' in df.columns:
            fig.add_trace(
                go.Histogram(x=df['packet_size'], name='Packet Size Distribution',
                           nbinsx=50, opacity=0.7),
                row=2, col=1
            )
        
        # Top source IPs
        if 'src_ip' in df.columns:
            top_ips = df['src_ip'].value_counts().head(10)
            fig.add_trace(
                go.Bar(x=top_ips.values, y=top_ips.index, 
                      orientation='h', name='Top Source IPs'),
                row=2, col=2
            )
        
        # Update layout
        fig.update_layout(
            height=800,
            template=self.theme,
            title_text="Network Traffic Overview Dashboard",
            showlegend=True
        )
        
        if save_path:
            fig.write_html(save_path)
        
        return fig
    
    def plot_anomaly_detection_results(self, df: pd.DataFrame, anomaly_results: Dict, 
                                     save_path: Optional[str] = None) -> go.Figure:
        """
        Visualize anomaly detection results
        
        Args:
            df: Original DataFrame
            anomaly_results: Results from anomaly detector
            save_path: Optional path to save the plot
            
        Returns:
            Plotly figure object
        """
        if not PLOTLY_AVAILABLE:
            print("Plotly not available for interactive plots")
            return None
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Model Comparison', 'Anomaly Distribution Over Time',
                          'Anomaly Scores Distribution', 'Top Anomalous Features'],
            specs=[[{"type": "bar"}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"type": "bar"}]]
        )
        
        # Model comparison
        model_names = []
        anomaly_counts = []
        for model, results in anomaly_results.items():
            if 'anomalies' in results:
                model_names.append(model.replace('_', ' ').title())
                anomaly_counts.append(results['anomalies'])
        
        if model_names:
            fig.add_trace(
                go.Bar(x=model_names, y=anomaly_counts, 
                      name='Anomalies Detected', 
                      marker_color=self.colors['anomaly']),
                row=1, col=1
            )
        
        # Anomaly distribution over time (if ensemble results available)
        if 'ensemble' in anomaly_results and 'datetime' in df.columns:
            df['anomaly'] = anomaly_results['ensemble']['predictions']
            df['datetime'] = pd.to_datetime(df['datetime'])
            
            anomaly_time = df[df['anomaly'] == -1].groupby(
                df['datetime'].dt.floor('H')).size()
            normal_time = df[df['anomaly'] == 1].groupby(
                df['datetime'].dt.floor('H')).size()
            
            if not anomaly_time.empty:
                fig.add_trace(
                    go.Scatter(x=anomaly_time.index, y=anomaly_time.values,
                              mode='lines+markers', name='Anomalies',
                              line=dict(color=self.colors['anomaly'])),
                    row=1, col=2
                )
            
            if not normal_time.empty:
                fig.add_trace(
                    go.Scatter(x=normal_time.index, y=normal_time.values,
                              mode='lines+markers', name='Normal Traffic',
                              line=dict(color=self.colors['normal'])),
                    row=1, col=2
                )
        
        # Anomaly scores distribution (if available)
        if 'isolation_forest' in anomaly_results and 'scores' in anomaly_results['isolation_forest']:
            scores = anomaly_results['isolation_forest']['scores']
            fig.add_trace(
                go.Histogram(x=scores, name='Anomaly Scores',
                           nbinsx=50, opacity=0.7,
                           marker_color=self.colors['primary']),
                row=2, col=1
            )
        
        # Feature importance (if available)
        if hasattr(self, 'feature_importance') and self.feature_importance:
            # Use isolation forest importance if available
            if 'isolation_forest' in self.feature_importance:
                importance = self.feature_importance['isolation_forest']
                feature_names = self.feature_columns[:len(importance)]
                
                # Get top 10 features
                top_indices = np.argsort(importance)[-10:]
                top_features = [feature_names[i] for i in top_indices]
                top_importance = importance[top_indices]
                
                fig.add_trace(
                    go.Bar(x=top_importance, y=top_features,
                          orientation='h', name='Feature Importance',
                          marker_color=self.colors['secondary']),
                    row=2, col=2
                )
        
        # Update layout
        fig.update_layout(
            height=800,
            template=self.theme,
            title_text="Anomaly Detection Results Dashboard",
            showlegend=True
        )
        
        if save_path:
            fig.write_html(save_path)
        
        return fig
    
    def plot_network_topology(self, df: pd.DataFrame, max_nodes: int = 50,
                            save_path: Optional[str] = None) -> go.Figure:
        """
        Create network topology visualization
        
        Args:
            df: Network traffic DataFrame
            max_nodes: Maximum number of nodes to display
            save_path: Optional path to save the plot
            
        Returns:
            Plotly figure object
        """
        if not PLOTLY_AVAILABLE or not NETWORKX_AVAILABLE:
            print("Plotly and NetworkX required for network topology")
            return None
        
        # Create network graph
        G = nx.Graph()
        
        # Add edges (connections between IPs)
        for _, row in df.head(1000).iterrows():  # Limit for performance
            if 'src_ip' in row and 'dst_ip' in row:
                src_ip = row['src_ip']
                dst_ip = row['dst_ip']
                
                if G.has_edge(src_ip, dst_ip):
                    G[src_ip][dst_ip]['weight'] += 1
                else:
                    G.add_edge(src_ip, dst_ip, weight=1)
        
        # Keep only top nodes by degree
        if len(G.nodes()) > max_nodes:
            top_nodes = sorted(G.nodes(), key=G.degree, reverse=True)[:max_nodes]
            G = G.subgraph(top_nodes)
        
        # Create layout
        pos = nx.spring_layout(G, k=1, iterations=50)
        
        # Extract node and edge information
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        node_x = []
        node_y = []
        node_text = []
        node_size = []
        node_color = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(f"{node}<br>Degree: {G.degree[node]}")
            node_size.append(10 + G.degree[node] * 2)
            
            # Color by IP type
            try:
                ip = ipaddress.ip_address(node)
                if ip.is_private:
                    node_color.append('lightblue')
                else:
                    node_color.append('orange')
            except:
                node_color.append('gray')
        
        # Create traces
        edge_trace = go.Scatter(x=edge_x, y=edge_y, mode='lines',
                               line=dict(width=0.5, color='#888'),
                               hoverinfo='none', showlegend=False)
        
        node_trace = go.Scatter(x=node_x, y=node_y, mode='markers+text',
                               marker=dict(size=node_size, color=node_color,
                                         line=dict(width=2, color='DarkSlateGrey')),
                               text=node_text, textposition="middle center",
                               hoverinfo='text', showlegend=False)
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title=dict(text='Network Topology Map', font=dict(size=16)),
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40),
                           annotations=[dict(
                               text="Network connections between IP addresses",
                               showarrow=False,
                               xref="paper", yref="paper",
                               x=0.005, y=-0.002,
                               xanchor='left', yanchor='bottom',
                               font=dict(size=12)
                           )],
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           template=self.theme
                       ))
        
        if save_path:
            fig.write_html(save_path)
        
        return fig
    
    def plot_geographic_analysis(self, df: pd.DataFrame, ip_locations: Optional[Dict] = None,
                               save_path: Optional[str] = None):
        """
        Create geographic analysis of network traffic
        
        Args:
            df: Network traffic DataFrame
            ip_locations: Dictionary mapping IPs to locations {'ip': {'lat': x, 'lon': y, 'country': 'XX'}}
            save_path: Optional path to save the map
        """
        if not FOLIUM_AVAILABLE:
            print("Folium not available for geographic visualization")
            return None
        
        # Create base map
        m = folium.Map(location=[20, 0], zoom_start=2)
        
        # If no location data provided, create sample data for demonstration
        if ip_locations is None:
            print("No IP location data provided. Skipping geographic analysis.")
            return m
        
        # Count connections by location
        location_counts = {}
        for _, row in df.iterrows():
            if 'src_ip' in row and row['src_ip'] in ip_locations:
                loc_info = ip_locations[row['src_ip']]
                key = (loc_info['lat'], loc_info['lon'])
                location_counts[key] = location_counts.get(key, 0) + 1
            
            if 'dst_ip' in row and row['dst_ip'] in ip_locations:
                loc_info = ip_locations[row['dst_ip']]
                key = (loc_info['lat'], loc_info['lon'])
                location_counts[key] = location_counts.get(key, 0) + 1
        
        # Add markers for each location
        max_count = max(location_counts.values()) if location_counts else 1
        for (lat, lon), count in location_counts.items():
            folium.CircleMarker(
                location=[lat, lon],
                radius=5 + (count / max_count) * 15,
                popup=f"Connections: {count}",
                color='red' if count > max_count * 0.7 else 'blue',
                fillOpacity=0.6
            ).add_to(m)
        
        # Add heatmap
        if location_counts:
            heat_data = [[lat, lon, count] for (lat, lon), count in location_counts.items()]
            plugins.HeatMap(heat_data).add_to(m)
        
        if save_path:
            m.save(save_path)
        
        return m
    
    def plot_time_series_analysis(self, df: pd.DataFrame, 
                                save_path: Optional[str] = None) -> go.Figure:
        """
        Create detailed time series analysis
        
        Args:
            df: Network traffic DataFrame
            save_path: Optional path to save the plot
            
        Returns:
            Plotly figure object
        """
        if not PLOTLY_AVAILABLE:
            print("Plotly not available for time series plots")
            return None
        
        # Ensure datetime column
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        elif 'datetime' in df.columns:
            df['datetime'] = pd.to_datetime(df['datetime'])
        else:
            print("No timestamp data available")
            return None
        
        # Create subplots
        fig = make_subplots(
            rows=3, cols=1,
            subplot_titles=['Traffic Volume', 'Packet Size Over Time', 'Protocol Mix Over Time'],
            shared_xaxes=True,
            vertical_spacing=0.08
        )
        
        # Traffic volume over time (multiple granularities)
        hourly_traffic = df.groupby(df['datetime'].dt.floor('H')).size()
        daily_traffic = df.groupby(df['datetime'].dt.floor('D')).size()
        
        fig.add_trace(
            go.Scatter(x=hourly_traffic.index, y=hourly_traffic.values,
                      mode='lines', name='Hourly Traffic',
                      line=dict(color=self.colors['primary'])),
            row=1, col=1
        )
        
        # Average packet size over time
        if 'packet_size' in df.columns:
            avg_packet_size = df.groupby(df['datetime'].dt.floor('H'))['packet_size'].mean()
            fig.add_trace(
                go.Scatter(x=avg_packet_size.index, y=avg_packet_size.values,
                          mode='lines', name='Avg Packet Size',
                          line=dict(color=self.colors['secondary'])),
                row=2, col=1
            )
        
        # Protocol distribution over time
        if 'protocol' in df.columns:
            protocol_time = df.groupby([df['datetime'].dt.floor('H'), 'protocol']).size().unstack(fill_value=0)
            
            for i, protocol in enumerate(protocol_time.columns[:5]):  # Top 5 protocols
                fig.add_trace(
                    go.Scatter(x=protocol_time.index, y=protocol_time[protocol],
                              mode='lines', name=f'{protocol}',
                              stackgroup='one'),
                    row=3, col=1
                )
        
        # Update layout
        fig.update_layout(
            height=900,
            template=self.theme,
            title_text="Time Series Analysis Dashboard",
            showlegend=True
        )
        
        # Update x-axis labels
        fig.update_xaxes(title_text="Time", row=3, col=1)
        fig.update_yaxes(title_text="Packets/Hour", row=1, col=1)
        fig.update_yaxes(title_text="Avg Packet Size", row=2, col=1)
        fig.update_yaxes(title_text="Packets", row=3, col=1)
        
        if save_path:
            fig.write_html(save_path)
        
        return fig
    
    def plot_security_analysis(self, df: pd.DataFrame, threat_indicators: Optional[Dict] = None,
                             save_path: Optional[str] = None) -> go.Figure:
        """
        Create security-focused analysis dashboard
        
        Args:
            df: Network traffic DataFrame
            threat_indicators: Dictionary with threat intelligence data
            save_path: Optional path to save the plot
            
        Returns:
            Plotly figure object
        """
        if not PLOTLY_AVAILABLE:
            print("Plotly not available for security plots")
            return None
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Suspicious Ports Activity', 'Unusual Packet Sizes',
                          'High-Risk IP Communications', 'Attack Pattern Detection'],
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"type": "scatter"}, {"secondary_y": False}]]
        )
        
        # Suspicious ports analysis
        if 'dst_port' in df.columns:
            # Define suspicious ports
            suspicious_ports = [21, 22, 23, 135, 139, 445, 1433, 3389, 5432, 6379]
            port_counts = df['dst_port'].value_counts()
            
            suspicious_data = []
            for port in suspicious_ports:
                if port in port_counts.index:
                    suspicious_data.append((port, port_counts[port]))
            
            if suspicious_data:
                ports, counts = zip(*suspicious_data)
                fig.add_trace(
                    go.Bar(x=list(ports), y=list(counts),
                          name='Suspicious Ports',
                          marker_color=self.colors['anomaly']),
                    row=1, col=1
                )
        
        # Unusual packet sizes
        if 'packet_size' in df.columns:
            # Identify outliers using IQR
            Q1 = df['packet_size'].quantile(0.25)
            Q3 = df['packet_size'].quantile(0.75)
            IQR = Q3 - Q1
            outliers = df[(df['packet_size'] < (Q1 - 1.5 * IQR)) | 
                         (df['packet_size'] > (Q3 + 1.5 * IQR))]
            
            fig.add_trace(
                go.Histogram(x=df['packet_size'], name='Normal Traffic',
                           nbinsx=50, opacity=0.7, 
                           marker_color=self.colors['normal']),
                row=1, col=2
            )
            
            if len(outliers) > 0:
                fig.add_trace(
                    go.Histogram(x=outliers['packet_size'], name='Unusual Sizes',
                               nbinsx=20, opacity=0.7,
                               marker_color=self.colors['anomaly']),
                    row=1, col=2
                )
        
        # High-risk IP communications
        if 'src_ip' in df.columns and 'dst_ip' in df.columns:
            # Find IPs with high connection counts
            src_counts = df['src_ip'].value_counts()
            dst_counts = df['dst_ip'].value_counts()
            
            # Plot top communicating IPs
            top_src = src_counts.head(20)
            top_dst = dst_counts.head(20)
            
            fig.add_trace(
                go.Scatter(x=list(range(len(top_src))), y=top_src.values,
                          mode='markers', name='Top Source IPs',
                          text=top_src.index,
                          marker=dict(size=10, color=self.colors['primary'])),
                row=2, col=1
            )
            
            fig.add_trace(
                go.Scatter(x=list(range(len(top_dst))), y=top_dst.values,
                          mode='markers', name='Top Destination IPs',
                          text=top_dst.index,
                          marker=dict(size=10, color=self.colors['secondary'])),
                row=2, col=1
            )
        
        # Attack pattern detection (if threat indicators provided)
        if threat_indicators:
            pattern_counts = {}
            for pattern, count in threat_indicators.items():
                pattern_counts[pattern] = count
            
            if pattern_counts:
                fig.add_trace(
                    go.Bar(x=list(pattern_counts.keys()), 
                          y=list(pattern_counts.values()),
                          name='Attack Patterns',
                          marker_color=self.colors['suspicious']),
                    row=2, col=2
                )
        
        # Update layout
        fig.update_layout(
            height=800,
            template=self.theme,
            title_text="Security Analysis Dashboard",
            showlegend=True
        )
        
        if save_path:
            fig.write_html(save_path)
        
        return fig
    
    def create_comprehensive_report(self, df: pd.DataFrame, anomaly_results: Optional[Dict] = None,
                                  threat_indicators: Optional[Dict] = None,
                                  save_dir: str = "./reports/") -> Dict[str, str]:
        """
        Create comprehensive visualization report
        
        Args:
            df: Network traffic DataFrame
            anomaly_results: Results from anomaly detection
            threat_indicators: Threat intelligence data
            save_dir: Directory to save reports
            
        Returns:
            Dictionary with file paths of generated reports
        """
        report_files = {}
        
        report_files = {}
        
        # Traffic overview
        overview_fig = self.plot_traffic_overview(df)
        if overview_fig:
            overview_path = os.path.join(save_dir, "traffic_overview.html")
            overview_fig.write_html(overview_path)
            report_files['overview'] = overview_path
        
        # Anomaly detection results
        if anomaly_results:
            anomaly_fig = self.plot_anomaly_detection_results(df, anomaly_results)
            if anomaly_fig:
                anomaly_path = os.path.join(save_dir, "anomaly_detection.html")
                anomaly_fig.write_html(anomaly_path)
                report_files['anomaly'] = anomaly_path
        
        # Time series analysis
        time_fig = self.plot_time_series_analysis(df)
        if time_fig:
            time_path = os.path.join(save_dir, "time_series_analysis.html")
            time_fig.write_html(time_path)
            report_files['time_series'] = time_path
        
        # Security analysis
        security_fig = self.plot_security_analysis(df, threat_indicators)
        if security_fig:
            security_path = os.path.join(save_dir, "security_analysis.html")
            security_fig.write_html(security_path)
            report_files['security'] = security_path
        
        # Network topology
        topology_fig = self.plot_network_topology(df)
        if topology_fig:
            topology_path = os.path.join(save_dir, "network_topology.html")
            topology_fig.write_html(topology_path)
            report_files['topology'] = topology_path
        
        return report_files

# Example usage
if __name__ == "__main__":
    # Create sample data
    np.random.seed(42)
    n_samples = 1000
    
    # Generate sample network data
    protocols = ['TCP', 'UDP', 'ICMP']
    src_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    dst_ips = [f"10.0.0.{i}" for i in range(1, 50)]
    
    sample_data = {
        'timestamp': np.random.uniform(1609459200, 1609545600, n_samples),  # Jan 2021
        'src_ip': np.random.choice(src_ips, n_samples),
        'dst_ip': np.random.choice(dst_ips, n_samples),
        'protocol': np.random.choice(protocols, n_samples),
        'src_port': np.random.randint(1024, 65535, n_samples),
        'dst_port': np.random.choice([80, 443, 22, 21, 53, 25], n_samples),
        'packet_size': np.random.lognormal(6, 1, n_samples).astype(int)
    }
    
    df = pd.DataFrame(sample_data)
    
    # Initialize visualizer
    visualizer = NetworkTrafficVisualizer()
    
    # Create sample anomaly results
    anomaly_results = {
        'isolation_forest': {'anomalies': 50, 'anomaly_rate': 0.05},
        'one_class_svm': {'anomalies': 45, 'anomaly_rate': 0.045},
        'dbscan': {'anomalies': 60, 'anomaly_rate': 0.06},
        'ensemble': {'predictions': np.random.choice([-1, 1], n_samples, p=[0.05, 0.95])}
    }
    
    # Generate visualizations
    print("Generating network traffic visualizations...")
    
    # Create individual plots
    overview_fig = visualizer.plot_traffic_overview(df)
    anomaly_fig = visualizer.plot_anomaly_detection_results(df, anomaly_results)
    time_fig = visualizer.plot_time_series_analysis(df)
    
    print("Visualizations created successfully!")
    print("Use .show() to display plots in Jupyter notebook or .write_html() to save them.")
