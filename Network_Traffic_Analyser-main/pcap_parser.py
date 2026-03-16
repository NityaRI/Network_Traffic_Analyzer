"""
Advanced PCAP File Parser and Feature Extractor
Supports comprehensive network traffic analysis for security monitoring
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import hashlib
from collections import defaultdict, Counter
import ipaddress
import re
from typing import Dict, List, Tuple, Optional, Any

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    print("Warning: pyshark not available. Install with: pip install pyshark")
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: scapy not available. Install with: pip install scapy")
    SCAPY_AVAILABLE = False

class AdvancedPCAPParser:
    """Advanced PCAP parser with comprehensive feature extraction capabilities"""
    
    def __init__(self, pcap_file: str):
        """
        Initialize the PCAP parser
        
        Args:
            pcap_file: Path to the PCAP file
        """
        self.pcap_file = pcap_file
        self.flows = defaultdict(list)
        self.packets_data = []
        self.dns_queries = []
        self.http_requests = []
        self.suspicious_patterns = []
        
        # Network feature extractors
        self.feature_extractors = {
            'basic_features': self._extract_basic_features,
            'flow_features': self._extract_flow_features,
            'statistical_features': self._extract_statistical_features,
            'behavioral_features': self._extract_behavioral_features,
            'protocol_features': self._extract_protocol_features,
            'temporal_features': self._extract_temporal_features
        }
        
    def parse_pcap_scapy(self) -> pd.DataFrame:
        """
        Parse PCAP file using Scapy library
        
        Returns:
            DataFrame with extracted network features
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for this method")
            
        print(f"Reading PCAP file: {self.pcap_file}")
        packets = rdpcap(self.pcap_file)
        
        print(f"Processing {len(packets)} packets...")
        
        for i, packet in enumerate(packets):
            if i % 1000 == 0:
                print(f"Processed {i}/{len(packets)} packets")
                
            packet_data = self._extract_packet_features(packet, i)
            if packet_data:
                self.packets_data.append(packet_data)
                
        print("Creating DataFrame...")
        df = pd.DataFrame(self.packets_data)
        
        # Add derived features
        df = self._add_derived_features(df)
        
        return df
    
    def parse_pcap_pyshark(self) -> pd.DataFrame:
        """
        Parse PCAP file using PyShark library
        
        Returns:
            DataFrame with extracted network features
        """
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark is required for this method")
            
        print(f"Reading PCAP file: {self.pcap_file}")
        cap = pyshark.FileCapture(self.pcap_file)
        
        packet_count = 0
        for packet in cap:
            packet_data = self._extract_pyshark_features(packet, packet_count)
            if packet_data:
                self.packets_data.append(packet_data)
            
            packet_count += 1
            if packet_count % 1000 == 0:
                print(f"Processed {packet_count} packets")
        
        cap.close()
        print("Creating DataFrame...")
        df = pd.DataFrame(self.packets_data)
        
        # Add derived features
        df = self._add_derived_features(df)
        
        return df
    
    def _extract_packet_features(self, packet, packet_id: int) -> Optional[Dict]:
        """Extract comprehensive features from a single packet using Scapy"""
        try:
            packet_data = {
                'packet_id': packet_id,
                'timestamp': float(packet.time),
                'packet_size': len(packet),
            }
            
            # Basic network layer features
            if IP in packet:
                ip_layer = packet[IP]
                packet_data.update({
                    'src_ip': str(ip_layer.src),
                    'dst_ip': str(ip_layer.dst),
                    'ip_version': ip_layer.version,
                    'ip_header_length': ip_layer.ihl * 4,
                    'ip_tos': ip_layer.tos,
                    'ip_total_length': ip_layer.len,
                    'ip_identification': ip_layer.id,
                    'ip_flags': ip_layer.flags,
                    'ip_fragment_offset': ip_layer.frag,
                    'ip_ttl': ip_layer.ttl,
                    'ip_protocol': ip_layer.proto,
                    'ip_checksum': ip_layer.chksum
                })
                
                # Transport layer features
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_data.update({
                        'protocol': 'TCP',
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'tcp_seq': tcp_layer.seq,
                        'tcp_ack': tcp_layer.ack,
                        'tcp_header_length': tcp_layer.dataofs * 4,
                        'tcp_flags': int(tcp_layer.flags),
                        'tcp_window': tcp_layer.window,
                        'tcp_checksum': tcp_layer.chksum,
                        'tcp_urgent': tcp_layer.urgptr,
                        'tcp_options_length': len(tcp_layer.options) * 4 if tcp_layer.options else 0
                    })
                    
                    # TCP flags breakdown
                    flags = tcp_layer.flags
                    packet_data.update({
                        'tcp_flag_fin': bool(flags & 0x01),
                        'tcp_flag_syn': bool(flags & 0x02),
                        'tcp_flag_rst': bool(flags & 0x04),
                        'tcp_flag_psh': bool(flags & 0x08),
                        'tcp_flag_ack': bool(flags & 0x10),
                        'tcp_flag_urg': bool(flags & 0x20),
                        'tcp_flag_ece': bool(flags & 0x40),
                        'tcp_flag_cwr': bool(flags & 0x80)
                    })
                    
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_data.update({
                        'protocol': 'UDP',
                        'src_port': udp_layer.sport,
                        'dst_port': udp_layer.dport,
                        'udp_length': udp_layer.len,
                        'udp_checksum': udp_layer.chksum
                    })
                    
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    packet_data.update({
                        'protocol': 'ICMP',
                        'icmp_type': icmp_layer.type,
                        'icmp_code': icmp_layer.code,
                        'icmp_checksum': icmp_layer.chksum,
                        'icmp_id': icmp_layer.id if hasattr(icmp_layer, 'id') else 0
                    })
            
            # Application layer features
            self._extract_application_features(packet, packet_data)
            
            # Flow identification
            flow_key = self._generate_flow_key(packet_data)
            packet_data['flow_id'] = flow_key
            self.flows[flow_key].append(packet_data)
            
            return packet_data
            
        except Exception as e:
            print(f"Error processing packet {packet_id}: {e}")
            return None
    
    def _extract_pyshark_features(self, packet, packet_id: int) -> Optional[Dict]:
        """Extract features using PyShark"""
        try:
            packet_data = {
                'packet_id': packet_id,
                'timestamp': float(packet.sniff_timestamp),
                'packet_size': int(packet.length),
            }
            
            # Network layer
            if hasattr(packet, 'ip'):
                packet_data.update({
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'ip_version': int(packet.ip.version),
                    'ip_header_length': int(packet.ip.hdr_len),
                    'ip_tos': int(packet.ip.dsfield_dscp) if hasattr(packet.ip, 'dsfield_dscp') else 0,
                    'ip_total_length': int(packet.ip.len),
                    'ip_identification': int(packet.ip.id),
                    'ip_ttl': int(packet.ip.ttl),
                    'ip_protocol': int(packet.ip.proto)
                })
                
                # Transport layer
                if hasattr(packet, 'tcp'):
                    packet_data.update({
                        'protocol': 'TCP',
                        'src_port': int(packet.tcp.srcport),
                        'dst_port': int(packet.tcp.dstport),
                        'tcp_seq': int(packet.tcp.seq),
                        'tcp_ack': int(packet.tcp.ack),
                        'tcp_header_length': int(packet.tcp.hdr_len),
                        'tcp_window': int(packet.tcp.window_size),
                        'tcp_flags': int(packet.tcp.flags, 16) if hasattr(packet.tcp, 'flags') else 0
                    })
                    
                elif hasattr(packet, 'udp'):
                    packet_data.update({
                        'protocol': 'UDP',
                        'src_port': int(packet.udp.srcport),
                        'dst_port': int(packet.udp.dstport),
                        'udp_length': int(packet.udp.length)
                    })
                    
                elif hasattr(packet, 'icmp'):
                    packet_data.update({
                        'protocol': 'ICMP',
                        'icmp_type': int(packet.icmp.type),
                        'icmp_code': int(packet.icmp.code)
                    })
            
            return packet_data
            
        except Exception as e:
            print(f"Error processing packet {packet_id}: {e}")
            return None
    
    def _extract_application_features(self, packet, packet_data: Dict):
        """Extract application layer features"""
        # DNS analysis
        if DNS in packet:
            dns_layer = packet[DNS]
            packet_data.update({
                'application': 'DNS',
                'dns_id': dns_layer.id,
                'dns_qr': dns_layer.qr,
                'dns_opcode': dns_layer.opcode,
                'dns_rcode': dns_layer.rcode,
                'dns_qdcount': dns_layer.qdcount,
                'dns_ancount': dns_layer.ancount
            })
            
            if dns_layer.qd:
                packet_data['dns_query'] = str(dns_layer.qd.qname.decode('utf-8'))
                self.dns_queries.append({
                    'timestamp': packet_data['timestamp'],
                    'query': packet_data['dns_query'],
                    'src_ip': packet_data.get('src_ip', ''),
                    'qtype': dns_layer.qd.qtype
                })
        
        # HTTP analysis
        if HTTPRequest in packet:
            http_layer = packet[HTTPRequest]
            packet_data.update({
                'application': 'HTTP',
                'http_method': http_layer.Method.decode('utf-8') if http_layer.Method else '',
                'http_host': http_layer.Host.decode('utf-8') if http_layer.Host else '',
                'http_uri': http_layer.Path.decode('utf-8') if http_layer.Path else ''
            })
            
            self.http_requests.append({
                'timestamp': packet_data['timestamp'],
                'method': packet_data.get('http_method', ''),
                'host': packet_data.get('http_host', ''),
                'uri': packet_data.get('http_uri', ''),
                'src_ip': packet_data.get('src_ip', '')
            })
        
        # Raw payload analysis
        if Raw in packet:
            payload = packet[Raw].load
            packet_data.update({
                'payload_size': len(payload),
                'payload_entropy': self._calculate_entropy(payload)
            })
            
            # Detect suspicious patterns
            self._detect_suspicious_patterns(payload, packet_data)
    
    def _generate_flow_key(self, packet_data: Dict) -> str:
        """Generate unique flow identifier"""
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        protocol = packet_data.get('protocol', '')
        
        # Normalize flow direction
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
        return hashlib.md5(flow_key.encode()).hexdigest()[:16]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        counts = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * np.log2(p)
                
        return entropy
    
    def _detect_suspicious_patterns(self, payload: bytes, packet_data: Dict):
        """Detect suspicious patterns in payload"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            
            # SQL injection patterns
            sql_patterns = [
                'union select', 'drop table', 'insert into', 'delete from',
                'update set', 'exec(', 'execute(', 'sp_executesql'
            ]
            
            # XSS patterns
            xss_patterns = [
                '<script', 'javascript:', 'onerror=', 'onload=',
                'eval(', 'alert(', 'document.cookie'
            ]
            
            # Command injection patterns
            cmd_patterns = [
                'cmd.exe', '/bin/sh', 'powershell', 'bash',
                '&&', '||', ';cat', ';ls'
            ]
            
            suspicious_score = 0
            detected_patterns = []
            
            for pattern in sql_patterns:
                if pattern in payload_str:
                    suspicious_score += 3
                    detected_patterns.append(f"SQL:{pattern}")
            
            for pattern in xss_patterns:
                if pattern in payload_str:
                    suspicious_score += 2
                    detected_patterns.append(f"XSS:{pattern}")
            
            for pattern in cmd_patterns:
                if pattern in payload_str:
                    suspicious_score += 4
                    detected_patterns.append(f"CMD:{pattern}")
            
            if suspicious_score > 0:
                packet_data['suspicious_score'] = suspicious_score
                packet_data['suspicious_patterns'] = '|'.join(detected_patterns)
                
                self.suspicious_patterns.append({
                    'timestamp': packet_data['timestamp'],
                    'src_ip': packet_data.get('src_ip', ''),
                    'dst_ip': packet_data.get('dst_ip', ''),
                    'score': suspicious_score,
                    'patterns': detected_patterns
                })
                
        except Exception as e:
            pass  # Ignore decode errors
    
    def _add_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add derived features to the DataFrame"""
        if df.empty:
            return df
        
        print("Adding derived features...")
        
        # Time-based features
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        df['hour'] = df['datetime'].dt.hour
        df['day_of_week'] = df['datetime'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6])
        
        # Flow-based features
        flow_stats = df.groupby('flow_id').agg({
            'packet_size': ['count', 'sum', 'mean', 'std', 'min', 'max'],
            'timestamp': ['min', 'max']
        }).round(4)
        
        flow_stats.columns = ['_'.join(col) for col in flow_stats.columns]
        flow_stats['flow_duration'] = flow_stats['timestamp_max'] - flow_stats['timestamp_min']
        flow_stats['flow_rate'] = flow_stats['packet_size_sum'] / (flow_stats['flow_duration'] + 0.001)
        
        df = df.merge(flow_stats, left_on='flow_id', right_index=True, how='left')
        
        # Port-based features
        df['is_common_port'] = df['dst_port'].isin([21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995])
        df['is_high_port'] = df['dst_port'] > 1024
        
        # IP-based features
        def is_private_ip(ip):
            try:
                return ipaddress.ip_address(ip).is_private
            except:
                return False
        
        df['src_ip_private'] = df['src_ip'].apply(is_private_ip)
        df['dst_ip_private'] = df['dst_ip'].apply(is_private_ip)
        df['is_internal_traffic'] = df['src_ip_private'] & df['dst_ip_private']
        
        # Statistical features
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        for col in ['packet_size', 'tcp_window', 'ip_ttl']:
            if col in df.columns:
                df[f'{col}_zscore'] = (df[col] - df[col].mean()) / (df[col].std() + 0.001)
        
        # Binary encoding for categorical features
        if 'protocol' in df.columns:
            df = pd.get_dummies(df, columns=['protocol'], prefix='proto')
        
        print(f"Final DataFrame shape: {df.shape}")
        return df
    
    def _extract_basic_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Extract basic network statistics"""
        return {
            'total_packets': len(df),
            'unique_flows': df['flow_id'].nunique() if 'flow_id' in df.columns else 0,
            'unique_src_ips': df['src_ip'].nunique() if 'src_ip' in df.columns else 0,
            'unique_dst_ips': df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0,
            'protocol_distribution': df['protocol'].value_counts().to_dict() if 'protocol' in df.columns else {},
            'avg_packet_size': df['packet_size'].mean() if 'packet_size' in df.columns else 0,
            'total_bytes': df['packet_size'].sum() if 'packet_size' in df.columns else 0
        }
    
    def _extract_flow_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Extract flow-based features"""
        if 'flow_id' not in df.columns:
            return {}
            
        flow_stats = df.groupby('flow_id').agg({
            'packet_size': ['count', 'sum', 'mean'],
            'timestamp': ['min', 'max']
        })
        
        flow_stats['duration'] = flow_stats[('timestamp', 'max')] - flow_stats[('timestamp', 'min')]
        
        return {
            'avg_flow_duration': flow_stats['duration'].mean(),
            'max_flow_duration': flow_stats['duration'].max(),
            'avg_packets_per_flow': flow_stats[('packet_size', 'count')].mean(),
            'avg_bytes_per_flow': flow_stats[('packet_size', 'sum')].mean()
        }
    
    def get_analysis_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        summary = {}
        
        for feature_type, extractor in self.feature_extractors.items():
            try:
                summary[feature_type] = extractor(df)
            except Exception as e:
                print(f"Error extracting {feature_type}: {e}")
                summary[feature_type] = {}
        
        # Add threat intelligence
        summary['dns_analysis'] = {
            'total_queries': len(self.dns_queries),
            'unique_domains': len(set(q['query'] for q in self.dns_queries)),
            'top_queried_domains': Counter(q['query'] for q in self.dns_queries).most_common(10)
        }
        
        summary['http_analysis'] = {
            'total_requests': len(self.http_requests),
            'unique_hosts': len(set(r['host'] for r in self.http_requests)),
            'methods_distribution': Counter(r['method'] for r in self.http_requests)
        }
        
        summary['security_analysis'] = {
            'suspicious_packets': len(self.suspicious_patterns),
            'high_risk_flows': len([p for p in self.suspicious_patterns if p['score'] >= 5]),
            'attack_patterns': Counter(pattern for p in self.suspicious_patterns for pattern in p['patterns'])
        }
        
        return summary
    
    def _extract_statistical_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Extract statistical features"""
        if df.empty:
            return {}
        
        stats = {}
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in ['packet_size', 'tcp_window', 'ip_ttl']:
            if col in df.columns:
                stats[f'{col}_stats'] = {
                    'mean': df[col].mean(),
                    'std': df[col].std(),
                    'min': df[col].min(),
                    'max': df[col].max(),
                    'median': df[col].median(),
                    'q75': df[col].quantile(0.75),
                    'q25': df[col].quantile(0.25)
                }
        
        return stats
    
    def _extract_behavioral_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Extract behavioral features"""
        if df.empty:
            return {}
        
        behavioral = {}
        
        # Time-based patterns
        if 'hour' in df.columns:
            behavioral['hourly_distribution'] = df['hour'].value_counts().to_dict()
            behavioral['peak_hour'] = df['hour'].mode().iloc[0] if not df['hour'].mode().empty else 0
        
        # Port scanning detection
        if 'dst_port' in df.columns and 'src_ip' in df.columns:
            port_scans = df.groupby('src_ip')['dst_port'].nunique()
            behavioral['potential_port_scans'] = len(port_scans[port_scans > 100])
        
        return behavioral
    
    def _extract_protocol_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Extract protocol-specific features"""
        if df.empty:
            return {}
        
        protocol_features = {}
        
        # TCP-specific features
        tcp_df = df[df['protocol'] == 'TCP'] if 'protocol' in df.columns else pd.DataFrame()
        if not tcp_df.empty:
            protocol_features['tcp'] = {
                'syn_packets': len(tcp_df[tcp_df.get('tcp_flag_syn', False) == True]),
                'ack_packets': len(tcp_df[tcp_df.get('tcp_flag_ack', False) == True]),
                'fin_packets': len(tcp_df[tcp_df.get('tcp_flag_fin', False) == True]),
                'rst_packets': len(tcp_df[tcp_df.get('tcp_flag_rst', False) == True]),
                'avg_window_size': tcp_df['tcp_window'].mean() if 'tcp_window' in tcp_df.columns else 0
            }
        
        return protocol_features
    
    def _extract_temporal_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Extract temporal features"""
        if df.empty or 'timestamp' not in df.columns:
            return {}
        
        df_sorted = df.sort_values('timestamp')
        time_diffs = df_sorted['timestamp'].diff().dropna()
        
        return {
            'capture_duration': df_sorted['timestamp'].max() - df_sorted['timestamp'].min(),
            'avg_packet_interval': time_diffs.mean(),
            'packet_rate': len(df) / (df_sorted['timestamp'].max() - df_sorted['timestamp'].min() + 0.001),
            'time_variance': time_diffs.var()
        }

# Example usage function
def analyze_pcap_file(pcap_path: str, use_scapy: bool = True) -> Tuple[pd.DataFrame, Dict, List]:
    """
    Analyze a PCAP file and return extracted features and summary
    
    Args:
        pcap_path: Path to PCAP file
        use_scapy: Whether to use Scapy (True) or PyShark (False)
    
    Returns:
        Tuple of (DataFrame with features, analysis summary, suspicious patterns)
    """
    parser = AdvancedPCAPParser(pcap_path)
    
    try:
        if use_scapy and SCAPY_AVAILABLE:
            df = parser.parse_pcap_scapy()
        elif PYSHARK_AVAILABLE:
            df = parser.parse_pcap_pyshark()
        else:
            raise ImportError("Neither Scapy nor PyShark is available")
        
        summary = parser.get_analysis_summary(df)
        
        return df, summary, parser.suspicious_patterns
        
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")
        return pd.DataFrame(), {}, []

if __name__ == "__main__":
    # Example usage
    pcap_file = "sample.pcap"  # Replace with your PCAP file path
    
    try:
        df, summary = analyze_pcap_file(pcap_file)
        
        print(f"Extracted {len(df)} packet records")
        print(f"Number of features: {len(df.columns)}")
        print("\nSample features:")
        for col in df.columns[:10]:
            print(f"- {col}")
        
        print(f"\nAnalysis Summary:")
        for category, data in summary.items():
            print(f"{category}: {data}")
            
    except Exception as e:
        print(f"Error: {e}")
        print("Please ensure you have a PCAP file and the required libraries installed:")
        print("pip install scapy pyshark pandas numpy")
