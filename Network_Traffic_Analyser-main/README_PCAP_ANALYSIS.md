# Advanced Network Traffic Analysis - PCAP Edition

A comprehensive network security analysis system that processes PCAP files with advanced machine learning-based anomaly detection, threat intelligence integration, and interactive visualizations.

## 🚀 Features

### Core Capabilities
- **Advanced PCAP Parsing**: Direct analysis of .pcap, .pcapng, and .cap files using Scapy/PyShark
- **Multi-Algorithm Anomaly Detection**: Isolation Forest, One-Class SVM, DBSCAN, and Neural Network approaches
- **Real-time Monitoring**: Live network traffic capture and analysis capabilities
- **Threat Intelligence Integration**: IP reputation checking and attack pattern detection
- **Interactive Visualizations**: Comprehensive dashboards with Plotly, NetworkX, and Folium
- **Comprehensive Reporting**: Automated report generation with actionable insights

### Enhanced Features Over CSV Analysis
- **Deep Packet Inspection**: Extract 50+ network features from raw packets
- **Flow Analysis**: Connection tracking and flow-based anomaly detection
- **Protocol Intelligence**: TCP/UDP/ICMP/DNS/HTTP layer analysis
- **Network Topology Mapping**: Visual representation of network communications
- **Geographic Analysis**: IP geolocation and mapping capabilities
- **Payload Analysis**: Content inspection for attack signatures

## 📋 Requirements

### Python Dependencies
```bash
pip install pandas numpy scikit-learn matplotlib seaborn plotly
pip install scapy pyshark networkx folium
pip install tensorflow  # Optional, for neural network models
pip install flask requests hashlib ipaddress
```

### System Requirements
- Python 3.8+
- 4GB+ RAM (8GB recommended for large PCAP files)
- Network interface access (for live capture)
- Administrative privileges (for packet capture)

## 🛠️ Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd traffic-network-analysis
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Install system dependencies** (Linux/macOS):
```bash
# For packet capture capabilities
sudo apt-get install libpcap-dev  # Ubuntu/Debian
brew install libpcap              # macOS
```

4. **Set up directories**:
```bash
mkdir uploads reports output threat_intel_cache
```

## 🚀 Quick Start

### Web Interface
1. **Start the Flask application**:
```bash
python app.py
```

2. **Access the PCAP analysis interface**:
```
http://localhost:5000/pcap
```

3. **Upload a PCAP file** and wait for comprehensive analysis results.

### Command Line Usage
```python
from pcap_parser import analyze_pcap_file
from anomaly_detector import NetworkAnomalyDetector
from network_visualizer import NetworkTrafficVisualizer

# Analyze PCAP file
df, summary = analyze_pcap_file('sample.pcap')

# Train anomaly detection models
detector = NetworkAnomalyDetector()
results = detector.fit(df)

# Generate visualizations
visualizer = NetworkTrafficVisualizer()
viz_files = visualizer.create_comprehensive_report(df, anomaly_results=results)
```

## 📊 Analysis Workflow

### 1. PCAP File Processing
- **File Validation**: Checks for supported PCAP formats
- **Packet Extraction**: Parses packets using Scapy/PyShark
- **Feature Engineering**: Extracts 50+ network features per packet
- **Flow Reconstruction**: Groups packets into bidirectional flows

### 2. Feature Categories

#### Basic Features
- Packet size, timestamp, protocol type
- Source/destination IPs and ports
- IP header fields (TTL, ToS, flags)

#### Transport Layer Features
- TCP flags, window size, sequence numbers
- UDP length and checksum
- ICMP type and code

#### Flow-Based Features
- Connection duration and packet counts
- Bytes per second and inter-arrival times
- Bidirectional flow statistics

#### Behavioral Features
- Communication patterns
- Port scanning detection
- Protocol anomalies

#### Application Layer Features
- DNS query analysis
- HTTP request inspection
- Payload entropy and signatures

### 3. Anomaly Detection

#### Multiple ML Algorithms
- **Isolation Forest**: Unsupervised outlier detection
- **One-Class SVM**: Support vector-based anomaly detection
- **DBSCAN**: Density-based clustering for anomalies
- **Autoencoders**: Neural network reconstruction errors

#### Ensemble Methods
- Combines predictions from multiple models
- Weighted voting with confidence scores
- Model agreement analysis

### 4. Threat Intelligence

#### IP Reputation Checking
- Integration with VirusTotal, OTX, and other feeds
- Local threat intelligence lists
- Tor exit node detection

#### Attack Pattern Detection
- SQL injection signatures
- Cross-site scripting (XSS) patterns
- Command injection attempts
- Suspicious port activities

### 5. Visualization and Reporting

#### Interactive Dashboards
- Traffic overview with time series
- Protocol distribution analysis
- Network topology maps
- Geographic traffic visualization

#### Comprehensive Reports
- Executive summaries
- Technical analysis details
- Actionable security recommendations
- Export capabilities (HTML, PDF)

## 🔧 Configuration

### Anomaly Detection Parameters
```python
config = {
    'isolation_forest': {
        'contamination': 0.1,  # Expected anomaly rate
        'n_estimators': 100,
        'random_state': 42
    },
    'one_class_svm': {
        'nu': 0.1,  # Anomaly rate upper bound
        'kernel': 'rbf',
        'gamma': 'scale'
    },
    'autoencoder': {
        'encoding_dim': 32,
        'epochs': 50,
        'threshold_percentile': 95
    }
}
```

### Threat Intelligence Setup
```python
api_keys = {
    'virustotal': 'your-vt-api-key',
    'otx': 'your-otx-api-key'
}

threat_intel = ThreatIntelligence(
    api_keys=api_keys,
    offline_mode=False,  # Set to True for offline operation
    cache_dir='./threat_intel_cache'
)
```

## 📈 Performance Optimization

### For Large PCAP Files
- Process files in batches of 10,000-50,000 packets
- Use multiprocessing for feature extraction
- Enable data sampling for initial analysis

### Memory Management
```python
# Use memory-efficient processing
parser = AdvancedPCAPParser(pcap_file)
for batch in parser.process_in_batches(batch_size=10000):
    # Process each batch separately
    results = detector.predict(batch)
```

## 🔍 Real-time Monitoring

### Live Traffic Capture
```python
from realtime_monitor import RealTimeNetworkMonitor

# Initialize monitor
monitor = RealTimeNetworkMonitor(
    interface='eth0',  # Your network interface
    window_size=300,   # 5-minute sliding window
    threat_intel=threat_intel
)

# Start monitoring with callback for alerts
def alert_callback(alert):
    print(f"ALERT: {alert['type']} - {alert['details']}")

monitor.start_monitoring(callback=alert_callback)
```

### Alert Types
- **Anomaly Alerts**: Statistical deviations from normal traffic
- **Threat Alerts**: Known malicious IPs or attack patterns
- **Behavioral Alerts**: Unusual communication patterns

## 📚 API Reference

### Key Classes

#### AdvancedPCAPParser
```python
parser = AdvancedPCAPParser('sample.pcap')
df, summary = parser.parse_pcap_scapy()
```

#### NetworkAnomalyDetector
```python
detector = NetworkAnomalyDetector()
results = detector.fit(df)
predictions = detector.predict(new_df)
report = detector.generate_report(df)
```

#### NetworkTrafficVisualizer
```python
visualizer = NetworkTrafficVisualizer()
overview_fig = visualizer.plot_traffic_overview(df)
anomaly_fig = visualizer.plot_anomaly_detection_results(df, results)
topology_fig = visualizer.plot_network_topology(df)
```

#### ThreatIntelligence
```python
threat_intel = ThreatIntelligence(api_keys=api_keys)
reputation = threat_intel.check_ip_reputation('1.2.3.4')
threat_analysis = threat_intel.analyze_packet_threats(packet_data)
```

## 🎯 Use Cases

### Network Security Monitoring
- Monitor network perimeters for intrusions
- Detect lateral movement and data exfiltration
- Identify compromised devices

### Forensic Analysis
- Investigate security incidents
- Reconstruct attack timelines
- Identify indicators of compromise (IoCs)

### Network Troubleshooting
- Identify performance bottlenecks
- Analyze protocol distributions
- Monitor service availability

### Compliance Monitoring
- Log network activities for compliance
- Generate audit reports
- Monitor data flows

## 🔒 Security Considerations

### Data Privacy
- PCAP files may contain sensitive information
- Implement appropriate data handling procedures
- Consider data anonymization for analysis

### Access Control
- Restrict access to analysis system
- Implement user authentication
- Monitor system access logs

### Threat Intelligence
- Validate threat intelligence sources
- Implement rate limiting for API calls
- Cache results to reduce external dependencies

## 🐛 Troubleshooting

### Common Issues

#### PCAP Parsing Errors
```python
# Check file format and permissions
if not os.path.exists(pcap_file):
    print("PCAP file not found")
    
# Verify file format
file_type = magic.from_file(pcap_file)
print(f"File type: {file_type}")
```

#### Memory Issues
```python
# Monitor memory usage
import psutil
print(f"Memory usage: {psutil.virtual_memory().percent}%")

# Use batch processing for large files
for batch in process_in_batches(df, batch_size=1000):
    results = analyze_batch(batch)
```

#### Network Interface Access
```bash
# Linux: Check interface permissions
sudo tcpdump -i eth0 -c 1

# Windows: Run as Administrator
# Ensure WinPcap/Npcap is installed
```

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Update documentation
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Scikit-learn**: Machine learning algorithms
- **Plotly**: Interactive visualizations
- **NetworkX**: Network analysis and visualization
- **TensorFlow**: Neural network implementations

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review example notebooks
- Join our community discussions

---

**Note**: This system is designed for legitimate network security analysis. Users are responsible for ensuring compliance with applicable laws and regulations regarding network monitoring and data privacy.
