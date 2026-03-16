"""
Real-time Network Traffic Monitoring and Threat Intelligence
Provides continuous monitoring capabilities with threat intelligence integration
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import threading
import queue
import json
import socket
import hashlib
import requests
import os
import logging
import warnings
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
from collections import deque, defaultdict, Counter

try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Install with: pip install scapy")
    SCAPY_AVAILABLE = False

# Local imports - these should be in the same directory
try:
    from pcap_parser import AdvancedPCAPParser
    from anomaly_detector import NetworkAnomalyDetector
    from network_visualizer import NetworkTrafficVisualizer
except ImportError:
    print("Warning: Local modules not found. Make sure they're in the same directory.")

warnings.filterwarnings('ignore')

class ThreatIntelligence:
    """Fetches and manages threat intelligence data."""

    def __init__(self, api_keys=None, offline_mode=False, cache_dir='./threat_intel_cache'):
        """Initializes the threat intelligence module."""
        self.api_keys = api_keys or {}
        self.offline_mode = offline_mode
        self.cache_dir = cache_dir
        self.ip_cache = {}
        os.makedirs(self.cache_dir, exist_ok=True)

    def check_ip_reputation(self, ip_address):
        """Checks the reputation of an IP address using VirusTotal."""
        if self.offline_mode or not self.api_keys.get('virustotal'):
            return None
        
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": self.api_keys['virustotal']}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()['data']['attributes']['last_analysis_stats']
                self.ip_cache[ip_address] = data
                return data
            return None
        except requests.RequestException:
            return None
    
    def _load_cached_data(self):
        """Load previously cached threat intelligence data"""
        try:
            cache_file = os.path.join(self.cache_dir, "ip_cache.json")
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    self.cache = json.load(f)
                self.logger.info(f"Loaded {len(self.cache)} IP reputation records from cache")
        except Exception as e:
            self.logger.error(f"Error loading cached data: {str(e)}")
    
    def _save_cached_data(self):
        """Save threat intelligence data to cache"""
        try:
            cache_file = os.path.join(self.cache_dir, "ip_cache.json")
            with open(cache_file, 'w') as f:
                json.dump(self.cache, f)
            self.logger.info(f"Saved {len(self.cache)} IP reputation records to cache")
        except Exception as e:
            self.logger.error(f"Error saving cached data: {str(e)}")
    
    def _load_builtin_threat_intel(self):
        """Load built-in threat intelligence lists"""
        try:
            # Load malicious IPs
            malicious_ips_file = os.path.join(self.cache_dir, "malicious_ips.txt")
            if os.path.exists(malicious_ips_file):
                with open(malicious_ips_file, 'r') as f:
                    self.known_malicious_ips = set(line.strip() for line in f if line.strip())
                self.logger.info(f"Loaded {len(self.known_malicious_ips)} known malicious IPs")
            
            # Load C2 domains
            c2_domains_file = os.path.join(self.cache_dir, "c2_domains.txt")
            if os.path.exists(c2_domains_file):
                with open(c2_domains_file, 'r') as f:
                    self.known_c2_domains = set(line.strip() for line in f if line.strip())
                self.logger.info(f"Loaded {len(self.known_c2_domains)} known C2 domains")
            
            # Load Tor exit nodes
            tor_nodes_file = os.path.join(self.cache_dir, "tor_exit_nodes.txt")
            if os.path.exists(tor_nodes_file):
                with open(tor_nodes_file, 'r') as f:
                    self.tor_exit_nodes = set(line.strip() for line in f if line.strip())
                self.logger.info(f"Loaded {len(self.tor_exit_nodes)} Tor exit nodes")
        except Exception as e:
            self.logger.error(f"Error loading built-in threat intel: {str(e)}")
    
    def update_threat_intelligence(self):
        """Update threat intelligence from online sources"""
        if self.offline_mode:
            self.logger.info("Running in offline mode, skipping online updates")
            return
        
        self._update_tor_exit_nodes()
        self._update_malicious_ips()
        self._update_c2_domains()
        
        # Save updated data
        self._save_cached_data()
    
    def _update_tor_exit_nodes(self):
        """Update list of Tor exit nodes"""
        try:
            url = "https://check.torproject.org/exit-addresses"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Parse Tor exit nodes from the response
                exit_nodes = set()
                for line in response.text.splitlines():
                    if line.startswith("ExitAddress"):
                        parts = line.split()
                        if len(parts) >= 2:
                            exit_nodes.add(parts[1])
                
                self.tor_exit_nodes = exit_nodes
                self.logger.info(f"Updated Tor exit nodes list: {len(self.tor_exit_nodes)} nodes")
                
                # Save to file
                with open(os.path.join(self.cache_dir, "tor_exit_nodes.txt"), 'w') as f:
                    for node in self.tor_exit_nodes:
                        f.write(f"{node}\n")
        except Exception as e:
            self.logger.error(f"Error updating Tor exit nodes: {str(e)}")
    
    def _update_malicious_ips(self):
        """Update list of known malicious IPs"""
        # This would typically connect to threat intel feeds
        # For demonstration, we'll use a simple example
        try:
            # Example: Update from AlienVault OTX (requires API key)
            if 'otx' in self.api_keys:
                url = "https://otx.alienvault.com/api/v1/indicators/IPv4/reputation"
                headers = {'X-OTX-API-KEY': self.api_keys['otx']}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'reputation' in data:
                        for ip_data in data['reputation']:
                            if ip_data.get('threat_score', 0) > 2:
                                self.known_malicious_ips.add(ip_data['ip'])
                    self.logger.info(f"Updated malicious IPs list: {len(self.known_malicious_ips)} IPs")
        except Exception as e:
            self.logger.error(f"Error updating malicious IPs: {str(e)}")
    
    def _update_c2_domains(self):
        """Update list of known C2 domains"""
        # Similar to updating malicious IPs, but for domains
        pass
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check the reputation of an IP address
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with reputation information
        """
        # Check cache first
        if ip in self.cache:
            self.logger.debug(f"IP {ip} found in cache")
            return self.cache[ip]
        
        # Check built-in lists
        is_malicious = ip in self.known_malicious_ips
        is_tor_exit = ip in self.tor_exit_nodes
        
        if is_malicious or is_tor_exit:
            result = {
                'ip': ip,
                'reputation': 'malicious' if is_malicious else 'suspicious',
                'categories': [],
                'score': 100 if is_malicious else 70,
                'is_tor': is_tor_exit,
                'last_updated': datetime.now().isoformat(),
                'source': 'local'
            }
            if is_malicious:
                result['categories'].append('malicious')
            if is_tor_exit:
                result['categories'].append('tor')
            
            self.cache[ip] = result
            return result
        
        # If in offline mode, return minimal info
        if self.offline_mode:
            return {
                'ip': ip,
                'reputation': 'unknown',
                'categories': [],
                'score': 0,
                'is_tor': False,
                'last_updated': datetime.now().isoformat(),
                'source': 'offline'
            }
        
        # Try online services if available
        try:
            result = self._check_online_reputation(ip)
            self.cache[ip] = result
            return result
        except Exception as e:
            self.logger.error(f"Error checking IP reputation for {ip}: {str(e)}")
            return {
                'ip': ip,
                'reputation': 'error',
                'categories': [],
                'score': 0,
                'is_tor': False,
                'error': str(e),
                'last_updated': datetime.now().isoformat(),
                'source': 'error'
            }
    
    def _check_online_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation with online services"""
        # Check with VirusTotal if API key is available
        if 'virustotal' in self.api_keys:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {'x-apikey': self.api_keys['virustotal']}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    # Extract reputation data
                    reputation = attributes.get('reputation', 0)
                    categories = []
                    for engine, category in attributes.get('last_analysis_results', {}).items():
                        if category.get('category') == 'malicious':
                            categories.append(engine)
                    
                    malicious_count = len(categories)
                    total_engines = len(attributes.get('last_analysis_results', {}))
                    
                    score = 0
                    if total_engines > 0:
                        score = (malicious_count / total_engines) * 100
                    
                    return {
                        'ip': ip,
                        'reputation': 'malicious' if score > 20 else 'suspicious' if score > 0 else 'clean',
                        'categories': categories,
                        'score': score,
                        'is_tor': False,  # VirusTotal doesn't specifically report Tor
                        'last_updated': datetime.now().isoformat(),
                        'source': 'virustotal'
                    }
            except Exception as e:
                self.logger.error(f"Error with VirusTotal API: {str(e)}")
        
        # Fallback to a free service or return unknown
        return {
            'ip': ip,
            'reputation': 'unknown',
            'categories': [],
            'score': 0,
            'is_tor': False,
            'last_updated': datetime.now().isoformat(),
            'source': 'none'
        }
    
    def analyze_packet_threats(self, packet_data: Dict) -> Dict:
        """
        Analyze a packet for threat indicators
        
        Args:
            packet_data: Dictionary with packet information
            
        Returns:
            Dictionary with threat analysis
        """
        threat_score = 0
        threat_indicators = []
        
        # Check source IP
        if 'src_ip' in packet_data:
            src_ip = packet_data['src_ip']
            src_rep = self.check_ip_reputation(src_ip)
            if src_rep['reputation'] == 'malicious':
                threat_score += 50
                threat_indicators.append(f"Malicious source IP: {src_ip}")
            elif src_rep['reputation'] == 'suspicious':
                threat_score += 20
                threat_indicators.append(f"Suspicious source IP: {src_ip}")
            
            if src_rep['is_tor']:
                threat_score += 30
                threat_indicators.append(f"Tor exit node: {src_ip}")
        
        # Check destination IP
        if 'dst_ip' in packet_data:
            dst_ip = packet_data['dst_ip']
            dst_rep = self.check_ip_reputation(dst_ip)
            if dst_rep['reputation'] == 'malicious':
                threat_score += 50
                threat_indicators.append(f"Malicious destination IP: {dst_ip}")
            elif dst_rep['reputation'] == 'suspicious':
                threat_score += 20
                threat_indicators.append(f"Suspicious destination IP: {dst_ip}")
        
        # Check suspicious ports
        if 'dst_port' in packet_data and packet_data['dst_port'] in self.suspicious_ports:
            threat_score += 10
            threat_indicators.append(f"Suspicious port: {packet_data['dst_port']}")
        
        # Check for known attack patterns
        if 'payload' in packet_data:
            # This would check the payload for attack signatures
            # For demo, we'll just check for some simple patterns
            payload = packet_data.get('payload', '')
            if isinstance(payload, bytes):
                payload_str = payload.decode('latin-1').lower()
                
                if 'eval(' in payload_str or 'exec(' in payload_str:
                    threat_score += 30
                    threat_indicators.append("Code execution attempt detected")
                
                if 'union select' in payload_str or 'drop table' in payload_str:
                    threat_score += 40
                    threat_indicators.append("SQL injection attempt detected")
        
        # Return threat analysis
        return {
            'threat_score': min(100, threat_score),
            'threat_level': 'high' if threat_score > 60 else 'medium' if threat_score > 30 else 'low',
            'threat_indicators': threat_indicators,
            'timestamp': datetime.now().isoformat()
        }


class RealTimeNetworkMonitor:
    """Real-time network traffic monitoring with threat detection"""
    
    def __init__(self, interface: Optional[str] = None, 
                window_size: int = 300,
                anomaly_model_path: Optional[str] = None,
                threat_intel: Optional[ThreatIntelligence] = None,
                output_dir: str = "./output/"):
        """
        Initialize the real-time monitor
        
        Args:
            interface: Network interface to monitor (None for offline mode)
            window_size: Size of sliding window in seconds
            anomaly_model_path: Path to pre-trained anomaly detection model
            threat_intel: Threat intelligence instance
            output_dir: Directory for output files
        """
        self.interface = interface
        self.window_size = window_size
        self.output_dir = output_dir
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Initialize data structures
        self.packet_queue = queue.Queue()
        self.sliding_window = deque(maxlen=10000)  # Store recent packets
        self.traffic_stats = defaultdict(int)
        self.alerts = []
        self.monitoring = False
        self.sniff_thread = None
        
        # Load anomaly detection model
        self.anomaly_detector = NetworkAnomalyDetector()
        if anomaly_model_path and os.path.exists(anomaly_model_path):
            try:
                self.anomaly_detector.load_models(anomaly_model_path)
                self.logger.info(f"Loaded anomaly detection model from {anomaly_model_path}")
            except Exception as e:
                self.logger.error(f"Error loading anomaly model: {str(e)}")
        
        # Initialize threat intelligence
        self.threat_intel = threat_intel or ThreatIntelligence(offline_mode=True)
        
        # Initialize visualizer
        self.visualizer = NetworkTrafficVisualizer()
    
    def start_monitoring(self, callback: Optional[Callable] = None):
        """
        Start real-time network monitoring
        
        Args:
            callback: Optional callback function to be called when alerts are generated
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot start monitoring.")
            return
        
        if self.monitoring:
            self.logger.warning("Monitoring already in progress")
            return
        
        self.monitoring = True
        
        # Start packet processing thread
        processing_thread = threading.Thread(
            target=self._process_packets,
            args=(callback,),
            daemon=True
        )
        processing_thread.start()
        
        # Start packet sniffing if interface provided
        if self.interface:
            self.logger.info(f"Starting live capture on interface {self.interface}")
            self.sniff_thread = threading.Thread(
                target=self._sniff_packets,
                daemon=True
            )
            self.sniff_thread.start()
            
            self.logger.info("Real-time monitoring started")
        else:
            self.logger.info("Started in offline mode (no interface specified)")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        self.logger.info("Stopping monitoring")
        
        # Wait for threads to complete
        if self.sniff_thread and self.sniff_thread.is_alive():
            # Can't directly stop sniff(), but will stop processing
            self.logger.info("Waiting for sniffing to complete...")
            time.sleep(1)
        
        self.logger.info("Monitoring stopped")
    
    def _sniff_packets(self):
        """Sniff packets from network interface"""
        try:
            sniff(iface=self.interface, prn=self._packet_callback, store=0)
        except Exception as e:
            self.logger.error(f"Error in packet sniffing: {str(e)}")
            self.monitoring = False
    
    def _packet_callback(self, packet):
        """Callback function for each sniffed packet"""
        if not self.monitoring:
            return
        
        try:
            # Put packet in the queue for processing
            self.packet_queue.put(packet)
        except Exception as e:
            self.logger.error(f"Error in packet callback: {str(e)}")
    
    def _process_packets(self, callback: Optional[Callable] = None):
        """Process packets from the queue"""
        packet_batch = []
        last_analysis_time = time.time()
        
        while self.monitoring:
            try:
                # Get packet with timeout to allow checking monitoring flag
                try:
                    packet = self.packet_queue.get(timeout=0.1)
                    packet_data = self._extract_packet_features(packet)
                    
                    if packet_data:
                        # Add to sliding window
                        self.sliding_window.append(packet_data)
                        
                        # Update statistics
                        self._update_statistics(packet_data)
                        
                        # Add to batch for periodic analysis
                        packet_batch.append(packet_data)
                except queue.Empty:
                    pass
                
                # Periodically analyze batch
                current_time = time.time()
                if packet_batch and (current_time - last_analysis_time > 5):  # Analyze every 5 seconds
                    self._analyze_batch(packet_batch, callback)
                    packet_batch = []
                    last_analysis_time = current_time
                    
            except Exception as e:
                self.logger.error(f"Error processing packets: {str(e)}")
                time.sleep(1)  # Avoid tight loop in case of repeated errors
    
    def _extract_packet_features(self, packet) -> Optional[Dict]:
        """Extract features from a packet"""
        try:
            packet_data = {}
            
            # Basic packet info
            packet_data['timestamp'] = float(packet.time)
            packet_data['packet_size'] = len(packet)
            
            # Process IP layer
            if IP in packet:
                ip_layer = packet[IP]
                packet_data['src_ip'] = ip_layer.src
                packet_data['dst_ip'] = ip_layer.dst
                packet_data['ip_ttl'] = ip_layer.ttl
                packet_data['ip_protocol'] = ip_layer.proto
                
                # Process TCP layer
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_data['protocol'] = 'TCP'
                    packet_data['src_port'] = tcp_layer.sport
                    packet_data['dst_port'] = tcp_layer.dport
                    packet_data['tcp_flags'] = int(tcp_layer.flags)
                    packet_data['tcp_window'] = tcp_layer.window
                
                # Process UDP layer
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_data['protocol'] = 'UDP'
                    packet_data['src_port'] = udp_layer.sport
                    packet_data['dst_port'] = udp_layer.dport
                
                # Process ICMP layer
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    packet_data['protocol'] = 'ICMP'
                    packet_data['icmp_type'] = icmp_layer.type
                    packet_data['icmp_code'] = icmp_layer.code
                
                # Generate flow ID for tracking connections
                packet_data['flow_id'] = self._generate_flow_id(packet_data)
                
                return packet_data
            return None
        except Exception as e:
            self.logger.error(f"Error extracting packet features: {str(e)}")
            return None
    
    def _generate_flow_id(self, packet_data: Dict) -> str:
        """Generate a unique flow identifier"""
        if 'src_ip' not in packet_data or 'dst_ip' not in packet_data:
            return "unknown"
            
        src_ip = packet_data['src_ip']
        dst_ip = packet_data['dst_ip']
        protocol = packet_data.get('protocol', '')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        
        # Normalize direction (smaller IP first to treat both directions as same flow)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            flow_str = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            flow_str = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
        return hashlib.md5(flow_str.encode()).hexdigest()[:16]
    
    def _update_statistics(self, packet_data: Dict):
        """Update traffic statistics"""
        self.traffic_stats['total_packets'] += 1
        self.traffic_stats['total_bytes'] += packet_data.get('packet_size', 0)
        
        # Update protocol stats
        protocol = packet_data.get('protocol', 'Unknown')
        self.traffic_stats[f'protocol_{protocol}'] += 1
        
        # Update flow stats
        flow_id = packet_data.get('flow_id', 'unknown')
        self.traffic_stats[f'flow_{flow_id}'] += 1
        
        # Update IP stats
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        if src_ip:
            self.traffic_stats[f'src_ip_{src_ip}'] += 1
        if dst_ip:
            self.traffic_stats[f'dst_ip_{dst_ip}'] += 1
    
    def _analyze_batch(self, packet_batch: List[Dict], callback: Optional[Callable] = None):
        """Analyze a batch of packets for anomalies and threats"""
        if not packet_batch:
            return
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame(packet_batch)
        
        # Detect anomalies if model is trained
        anomalies = []
        if self.anomaly_detector.is_trained:
            try:
                predictions = self.anomaly_detector.predict(df)
                if 'isolation_forest' in predictions:
                    # Find anomalous packets
                    anomaly_indices = np.where(predictions['isolation_forest'] == -1)[0]
                    anomalies = [packet_batch[i] for i in anomaly_indices]
                    
                    if anomalies:
                        self.logger.info(f"Detected {len(anomalies)} anomalies in current batch")
            except Exception as e:
                self.logger.error(f"Error in anomaly detection: {str(e)}")
        
        # Threat intelligence analysis
        threats = []
        high_severity_threats = []
        
        # Analyze up to 20 packets for threats (can be resource intensive)
        for packet_data in packet_batch[:20]:
            try:
                threat_analysis = self.threat_intel.analyze_packet_threats(packet_data)
                if threat_analysis['threat_level'] != 'low':
                    threats.append({**packet_data, **threat_analysis})
                    
                    if threat_analysis['threat_level'] == 'high':
                        high_severity_threats.append({**packet_data, **threat_analysis})
            except Exception as e:
                self.logger.error(f"Error in threat analysis: {str(e)}")
        
        # Generate alerts
        current_time = datetime.now().isoformat()
        
        if anomalies:
            alert = {
                'type': 'anomaly',
                'timestamp': current_time,
                'details': f"Detected {len(anomalies)} anomalous packets",
                'anomalies': anomalies[:5]  # Include first 5 anomalies
            }
            self.alerts.append(alert)
            self.logger.warning(f"ALERT: {alert['details']}")
            
            if callback:
                callback(alert)
        
        if high_severity_threats:
            alert = {
                'type': 'threat',
                'timestamp': current_time,
                'severity': 'high',
                'details': f"Detected {len(high_severity_threats)} high severity threats",
                'threats': high_severity_threats
            }
            self.alerts.append(alert)
            self.logger.warning(f"ALERT: {alert['details']}")
            
            if callback:
                callback(alert)
        
        # Generate traffic report periodically
        if len(self.alerts) % 10 == 0:
            self._generate_traffic_report()
    
    def process_pcap_file(self, pcap_file: str, callback: Optional[Callable] = None):
        """
        Process an existing PCAP file
        
        Args:
            pcap_file: Path to PCAP file
            callback: Optional callback function for alerts
        """
        self.logger.info(f"Processing PCAP file: {pcap_file}")
        
        try:
            # Parse PCAP with our advanced parser
            parser = AdvancedPCAPParser(pcap_file)
            if SCAPY_AVAILABLE:
                df = parser.parse_pcap_scapy()
            else:
                self.logger.error("Scapy not available. Cannot process PCAP file.")
                return
            
            # If the anomaly detector is not trained, train it on this data
            if not self.anomaly_detector.is_trained:
                self.logger.info("Training anomaly detection model on PCAP data")
                self.anomaly_detector.fit(df)
                
                # Save the trained model
                model_path = os.path.join(self.output_dir, "anomaly_model")
                self.anomaly_detector.save_models(model_path)
                self.logger.info(f"Saved anomaly detection model to {model_path}")
            
            # Analyze packets in batches
            batch_size = 1000
            for i in range(0, len(df), batch_size):
                batch_df = df.iloc[i:i+batch_size]
                batch_packets = batch_df.to_dict('records')
                self._analyze_batch(batch_packets, callback)
                self.logger.info(f"Processed batch {i//batch_size + 1}/{(len(df) // batch_size) + 1}")
            
            # Generate comprehensive report
            self._generate_comprehensive_report(df)
            
            return df
        except Exception as e:
            self.logger.error(f"Error processing PCAP file: {str(e)}")
            return None
    
    def _generate_traffic_report(self):
        """Generate traffic statistics report"""
        report_file = os.path.join(self.output_dir, f"traffic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        # Get current statistics
        report = {
            'timestamp': datetime.now().isoformat(),
            'duration': self.window_size,
            'total_packets': self.traffic_stats['total_packets'],
            'total_bytes': self.traffic_stats['total_bytes'],
            'packets_per_second': self.traffic_stats['total_packets'] / self.window_size if self.window_size > 0 else 0,
            'bytes_per_second': self.traffic_stats['total_bytes'] / self.window_size if self.window_size > 0 else 0,
            'protocol_distribution': {},
            'top_talkers': [],
            'recent_alerts': self.alerts[-10:] if self.alerts else []
        }
        
        # Protocol distribution
        for key, value in self.traffic_stats.items():
            if key.startswith('protocol_'):
                protocol = key.replace('protocol_', '')
                report['protocol_distribution'][protocol] = value
        
        # Top talkers (source IPs)
        ip_counts = {}
        for key, value in self.traffic_stats.items():
            if key.startswith('src_ip_'):
                ip = key.replace('src_ip_', '')
                ip_counts[ip] = value
        
        report['top_talkers'] = sorted(
            [{'ip': ip, 'packets': count} for ip, count in ip_counts.items()],
            key=lambda x: x['packets'],
            reverse=True
        )[:10]  # Top 10
        
        # Write report
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.logger.info(f"Traffic report saved to {report_file}")
        except Exception as e:
            self.logger.error(f"Error saving traffic report: {str(e)}")
        
        return report
    
    def _generate_comprehensive_report(self, df: pd.DataFrame):
        """Generate comprehensive traffic analysis report"""
        try:
            # Create report directory
            report_dir = os.path.join(self.output_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(report_dir, exist_ok=True)
            
            # Extract summary from anomaly detector
            if self.anomaly_detector.is_trained:
                try:
                    anomaly_results = self.anomaly_detector.predict(df)
                    anomaly_report = self.anomaly_detector.generate_report(df)
                except Exception as e:
                    self.logger.error(f"Error generating anomaly report: {str(e)}")
                    anomaly_results = {}
                    anomaly_report = {}
            else:
                anomaly_results = {}
                anomaly_report = {}
            
            # Get threat indicators
            threat_indicators = {}
            for alert in self.alerts:
                if alert['type'] == 'threat':
                    for threat in alert.get('threats', []):
                        for indicator in threat.get('threat_indicators', []):
                            threat_indicators[indicator] = threat_indicators.get(indicator, 0) + 1
            
            # Generate visualizations
            try:
                report_files = self.visualizer.create_comprehensive_report(
                    df, 
                    anomaly_results=anomaly_results if self.anomaly_detector.is_trained else None,
                    threat_indicators=threat_indicators,
                    save_dir=report_dir
                )
                
                # Create summary report
                summary = {
                    'timestamp': datetime.now().isoformat(),
                    'analyzed_packets': len(df),
                    'duration': df['timestamp'].max() - df['timestamp'].min() if 'timestamp' in df.columns else 0,
                    'report_files': report_files,
                    'anomaly_summary': anomaly_report.get('summary', {}) if anomaly_report else {},
                    'threats_detected': len(self.alerts),
                    'top_threat_indicators': sorted(
                        [{'indicator': k, 'count': v} for k, v in threat_indicators.items()],
                        key=lambda x: x['count'],
                        reverse=True
                    )[:10]
                }
                
                # Write summary
                with open(os.path.join(report_dir, 'summary.json'), 'w') as f:
                    json.dump(summary, f, indent=2)
                
                self.logger.info(f"Comprehensive report saved to {report_dir}")
                return report_dir
            except Exception as e:
                self.logger.error(f"Error creating visualizations: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error generating comprehensive report: {str(e)}")
            return None
    
    def get_real_time_stats(self) -> Dict:
        """Get current real-time statistics"""
        current_time = datetime.now().isoformat()
        
        # Basic stats
        stats = {
            'timestamp': current_time,
            'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0,
            'total_packets': self.traffic_stats['total_packets'],
            'total_bytes': self.traffic_stats['total_bytes'],
            'recent_alerts': len(self.alerts),
            'protocols': {},
            'recent_anomalies': 0
        }
        
        # Protocol breakdown
        for key, value in self.traffic_stats.items():
            if key.startswith('protocol_'):
                protocol = key.replace('protocol_', '')
                stats['protocols'][protocol] = value
        
        # Count recent anomalies
        for alert in self.alerts[-20:]:
            if alert['type'] == 'anomaly':
                stats['recent_anomalies'] += 1
        
        return stats


# Example usage
if __name__ == "__main__":
    # Initialize threat intelligence
    threat_intel = ThreatIntelligence(offline_mode=True)
    
    # Initialize real-time monitor
    monitor = RealTimeNetworkMonitor(
        interface=None,  # Set to None for offline mode
        threat_intel=threat_intel
    )
    
    # Example callback function for alerts
    def alert_callback(alert):
        print(f"ALERT RECEIVED: {alert['type']} - {alert['details']}")
    
    # Process a PCAP file (if it exists)
    import os
    pcap_file = "sample.pcap"
    if os.path.exists(pcap_file):
        print(f"Processing PCAP file: {pcap_file}")
        df = monitor.process_pcap_file(pcap_file, callback=alert_callback)
        print(f"Processed {len(df) if df is not None else 0} packets")
    else:
        print(f"PCAP file not found: {pcap_file}")
        print("For live capture, specify a network interface and call start_monitoring()")
        
        # Example for live capture (uncomment to use)
        # monitor = RealTimeNetworkMonitor(
        #     interface="eth0",  # Change to your interface
        #     threat_intel=threat_intel
        # )
        # monitor.start_monitoring(callback=alert_callback)
        # try:
        #     while True:
        #         time.sleep(1)
        # except KeyboardInterrupt:
        #     monitor.stop_monitoring()
        #     print("Monitoring stopped")
