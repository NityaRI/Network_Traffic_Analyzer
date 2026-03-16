import os
import pandas as pd
from datetime import datetime
import json
import numpy as np

class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NpEncoder, self).default(obj)

# Import your project's modules
from pcap_parser import analyze_pcap_file
from anomaly_detector import NetworkAnomalyDetector
from network_visualizer import NetworkTrafficVisualizer

def run_batch_analysis(pcap_dir, reports_dir, summary_file):
    """
    Analyzes all PCAP files in a directory, generates reports, and provides a summary.

    Args:
        pcap_dir (str): Directory containing PCAP files.
        reports_dir (str): Directory to save analysis reports.
        summary_file (str): Path to save the summary of the batch analysis.
    """
    print(f"Starting batch analysis of PCAP files in: {pcap_dir}")
    os.makedirs(reports_dir, exist_ok=True)

    all_summaries = []
    pcap_files = [f for f in os.listdir(pcap_dir) if f.lower().endswith(('.pcap', '.pcapng', '.cap'))]

    if not pcap_files:
        print("No PCAP files found to analyze.")
        return

    for filename in pcap_files:
        filepath = os.path.join(pcap_dir, filename)
        print(f"\n--- Analyzing: {filename} ---")

        try:
            # 1. Parse the PCAP file
            df, pcap_summary = analyze_pcap_file(filepath)
            if df.empty:
                print(f"Skipping {filename} due to parsing error or no data.")
                all_summaries.append({
                    'file': filename, 
                    'status': 'Failed - Parsing Error',
                    'timestamp': datetime.now().isoformat()
                })
                continue

            # 2. Run anomaly detection
            detector = NetworkAnomalyDetector()
            anomaly_results = detector.fit(df)

            # 3. Generate visualizations
            file_report_dir = os.path.join(reports_dir, os.path.splitext(filename)[0])
            os.makedirs(file_report_dir, exist_ok=True)
            
            visualizer = NetworkTrafficVisualizer()
            viz_files = visualizer.create_comprehensive_report(
                df, 
                anomaly_results=anomaly_results, 
                save_dir=file_report_dir
            )

            # 4. Compile summary for this file
            file_summary = {
                'file': filename,
                'status': 'Success',
                'total_packets': len(df),
                'pcap_summary': pcap_summary,
                'anomaly_summary': {
                    model: {
                        'anomalies': res.get('anomalies', 0),
                        'anomaly_rate': f"{res.get('anomaly_rate', 0) * 100:.2f}%"
                    } for model, res in anomaly_results.items() if 'anomalies' in res
                },
                'report_location': file_report_dir,
                'visualization_files': viz_files,
                'timestamp': datetime.now().isoformat()
            }
            all_summaries.append(file_summary)
            print(f"Successfully analyzed {filename}.")

        except Exception as e:
            print(f"An error occurred while processing {filename}: {e}")
            all_summaries.append({
                'file': filename, 
                'status': f'Failed - {str(e)}',
                'timestamp': datetime.now().isoformat()
            })

    # Save the consolidated summary to a file
    with open(summary_file, 'w') as f:
        json.dump(all_summaries, f, indent=4, cls=NpEncoder)
    
    print(f"\nBatch analysis complete. Summary saved to {summary_file}")

if __name__ == '__main__':
    PCAP_DIRECTORY = "uploads"
    REPORTS_DIRECTORY = "reports/batch_analysis_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    SUMMARY_FILE = os.path.join(REPORTS_DIRECTORY, "batch_summary.json")

    run_batch_analysis(PCAP_DIRECTORY, REPORTS_DIRECTORY, SUMMARY_FILE)

