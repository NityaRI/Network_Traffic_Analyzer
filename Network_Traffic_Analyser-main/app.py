from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, Response, render_template_string
from flask_cors import CORS
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
import os
import traceback
import zipfile
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Union, Optional
import warnings
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import gc
import psutil
from functools import lru_cache
import hashlib
from werkzeug.utils import secure_filename
import time
import tempfile
import uuid

warnings.filterwarnings('ignore')

# Configure matplotlib for production
plt.style.use('default')
sns.set_palette("husl")
plt.rcParams['font.size'] = 10
plt.rcParams['figure.dpi'] = 100

# Import our advanced modules
try:
    from pcap_parser import AdvancedPCAPParser, analyze_pcap_file
    from anomaly_detector import NetworkAnomalyDetector
    from network_visualizer import NetworkTrafficVisualizer
    from realtime_monitor import RealTimeNetworkMonitor, ThreatIntelligence
    ADVANCED_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Advanced modules not available: {e}")
    ADVANCED_MODULES_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for all domains
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(tempfile.gettempdir(), 'uploads')
app.config['REPORT_FOLDER'] = os.path.join(tempfile.gettempdir(), 'reports')
app.config['MODEL_FOLDER'] = os.path.join(tempfile.gettempdir(), 'model')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
os.makedirs(app.config['MODEL_FOLDER'], exist_ok=True)

# Global analysis cache and progress tracking
analysis_cache = {}
analysis_progress = {}
analysis_results = {}


def create_basic_visualizations(df: pd.DataFrame, save_dir: str) -> List[str]:
    """Create basic visualizations when the advanced visualizer is not available."""
    import os
    viz_files = []
    
    try:
        # Protocol distribution
        if 'protocol' in df.columns:
            plt.figure(figsize=(10, 6))
            protocol_counts = df['protocol'].value_counts().head(10)
            plt.pie(protocol_counts.values, labels=protocol_counts.index, autopct='%1.1f%%')
            plt.title('Protocol Distribution')
            protocol_file = os.path.join(save_dir, 'protocol_distribution.png')
            plt.savefig(protocol_file)
            plt.close()
            viz_files.append(protocol_file)
    except Exception:
        pass
    
    try:
        # Packet size distribution
        if 'packet_size' in df.columns or 'length' in df.columns:
            plt.figure(figsize=(10, 6))
            size_col = 'packet_size' if 'packet_size' in df.columns else 'length'
            plt.hist(df[size_col].dropna(), bins=50, alpha=0.7)
            plt.title('Packet Size Distribution')
            plt.xlabel('Packet Size (bytes)')
            plt.ylabel('Frequency')
            size_file = os.path.join(save_dir, 'packet_size_distribution.png')
            plt.savefig(size_file)
            plt.close()
            viz_files.append(size_file)
    except Exception:
        pass
    
    try:
        # Traffic over time
        if 'timestamp' in df.columns or 'datetime' in df.columns:
            plt.figure(figsize=(12, 6))
            time_col = 'timestamp' if 'timestamp' in df.columns else 'datetime'
            df['temp_datetime'] = pd.to_datetime(df[time_col], unit='s' if time_col == 'timestamp' else None)
            hourly_traffic = df.groupby(df['temp_datetime'].dt.floor('H')).size()
            plt.plot(hourly_traffic.index, hourly_traffic.values, marker='o')
            plt.title('Traffic Over Time')
            plt.xlabel('Time')
            plt.ylabel('Packet Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            time_file = os.path.join(save_dir, 'traffic_timeline.png')
            plt.savefig(time_file)
            plt.close()
            viz_files.append(time_file)
    except Exception:
        pass
    
    return viz_files


def analyze_generic_csv(df: pd.DataFrame) -> Dict[str, Any]:
    """Perform a robust, schema-agnostic analysis on any CSV dataframe with optimized processing.

    Returns a dict containing:
    - data_profile: summary stats, dtypes, missing values
    - plots: base64 images for distributions, correlation, missingness, feature importance
    - anomaly: unsupervised anomaly detection summary
    - preview: HTML table of head
    - derived: column sums for numeric columns
    """
    result: Dict[str, Any] = {
        'data_profile': {},
        'plots': {},
        'anomaly': {},
        'preview': '',
        'derived': {}
    }
    
    # Optimize for large datasets
    if len(df) > 100000:
        # Sample data for visualization and analysis to maintain performance
        sample_size = min(50000, len(df))
        df_sample = df.sample(n=sample_size, random_state=42)
        logger.info(f"Large dataset detected ({len(df)} rows). Using sample of {sample_size} for analysis.")
    else:
        df_sample = df.copy()

    # Basic info
    try:
        memory_mb = float(df.memory_usage(deep=True).sum()) / (1024 * 1024)
    except Exception:
        memory_mb = None

    dtypes = {col: str(dtype) for col, dtype in df.dtypes.items()}
    missing = df.isna().sum().to_dict()

    # Basic numeric stats
    try:
        desc_html = df.describe(include='all', datetime_is_numeric=True).to_html(classes='table table-bordered', index=True)
    except Exception:
        desc_html = pd.DataFrame({'info': ['describe failed']}).to_html(classes='table table-bordered')

    result['data_profile'] = {
        'shape': {'rows': int(df.shape[0]), 'cols': int(df.shape[1])},
        'memory_mb': memory_mb,
        'dtypes': dtypes,
        'missing': missing,
        'describe_html': desc_html,
    }

    # Data preview
    try:
        result['preview'] = df.head(10).to_html(classes='table table-striped', table_id='csv-preview')
    except Exception:
        result['preview'] = '<p>Unable to render preview</p>'

    # Numeric / categorical separation
    numeric_df = df.select_dtypes(include=[np.number])
    categorical_df = df.select_dtypes(include=['object', 'category', 'bool'])

    # Column sums (numeric)
    try:
        numeric_sums = numeric_df.sum().to_dict()
        # Convert numpy/pandas types to JSON serializable types
        numeric_sums = {k: float(v) if isinstance(v, (np.floating, np.float64, np.float32)) 
                       else int(v) if isinstance(v, (np.integer, np.int64, np.int32)) 
                       else v for k, v in numeric_sums.items()}
    except Exception:
        numeric_sums = {}
    result['derived']['numeric_sums'] = numeric_sums

    # Plots: missingness bar
    try:
        missing_series = df.isna().sum().sort_values(ascending=False)
        if missing_series.sum() > 0:
            buf = io.BytesIO()
            plt.figure(figsize=(10, 6))
            missing_series.head(30).plot(kind='bar', color='#ef4444')
            plt.title('Missing Values per Column (Top 30)')
            plt.ylabel('Missing Count')
            plt.tight_layout()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            result['plots']['missing_bar'] = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass

    # Plots: correlation heatmap for numeric
    try:
        if numeric_df.shape[1] >= 2:
            corr = numeric_df.corr(numeric_only=True)
            buf = io.BytesIO()
            plt.figure(figsize=(12, 8))
            sns.heatmap(corr, cmap='coolwarm', annot=False)
            plt.title('Correlation Heatmap (Numeric Columns)')
            plt.tight_layout()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            result['plots']['correlation_heatmap'] = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass

    # Plots: numeric distributions (top 5 by variance)
    try:
        if numeric_df.shape[1] >= 1:
            var_cols = numeric_df.var().sort_values(ascending=False).head(min(5, numeric_df.shape[1])).index.tolist()
            buf = io.BytesIO()
            plt.figure(figsize=(12, 8))
            for i, col in enumerate(var_cols):
                plt.subplot(len(var_cols), 1, i+1)
                sns.histplot(numeric_df[col].dropna(), bins=30, kde=True, color='#3b82f6')
                plt.title(f'Distribution: {col}')
            plt.tight_layout()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            result['plots']['numeric_distributions'] = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass

    # Plots: categorical top frequencies (up to 5 columns)
    try:
        if categorical_df.shape[1] >= 1:
            top_cat_cols: List[str] = categorical_df.columns[:min(5, categorical_df.shape[1])].tolist()
            buf = io.BytesIO()
            rows = len(top_cat_cols)
            plt.figure(figsize=(12, max(3*rows, 4)))
            for i, col in enumerate(top_cat_cols):
                plt.subplot(rows, 1, i+1)
                value_counts = categorical_df[col].astype(str).value_counts().head(10)
                sns.barplot(x=value_counts.values, y=value_counts.index, color='#10b981')
                plt.title(f'Top Categories: {col}')
            plt.tight_layout()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            result['plots']['categorical_topfreq'] = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass

    # Unsupervised anomaly detection (IsolationForest)
    try:
        # Preprocess: get_dummies for categoricals, coerce others to numeric
        X = df.copy()
        # Convert datetimes to numeric timestamps if present
        for col in X.select_dtypes(include=['datetime64[ns]', 'datetimetz']).columns:
            X[col] = pd.to_datetime(X[col], errors='coerce').astype('int64') // 1_000_000_000
        # One-hot encode categoricals with limited cardinality (cap to avoid explosion)
        cat_cols = X.select_dtypes(include=['object', 'category', 'bool']).columns.tolist()
        if cat_cols:
            # Truncate rare categories to 'OTHER' to control dimensionality
            for col in cat_cols:
                vc = X[col].astype(str).value_counts()
                top = set(vc.head(50).index)  # cap at 50 levels per col
                X[col] = X[col].astype(str).where(X[col].astype(str).isin(top), 'OTHER')
            X = pd.get_dummies(X, columns=cat_cols, drop_first=True)
        # Coerce the rest
        for col in X.columns:
            if not np.issubdtype(X[col].dtype, np.number):
                X[col] = pd.to_numeric(X[col], errors='coerce')
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        if X.shape[1] >= 2 and X.shape[0] >= 10:
            iso = __import__('sklearn.ensemble', fromlist=['IsolationForest']).IsolationForest(
                n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1
            )
            iso.fit(X)
            pred = iso.predict(X)  # 1 normal, -1 anomaly
            scores = iso.decision_function(X)
            anomalies = int(np.sum(pred == -1))
            rate = float(anomalies) / max(1, int(len(pred)))
            result['anomaly'] = {
                'model': 'IsolationForest',
                'anomalies': anomalies,
                'anomaly_rate': f"{rate*100:.2f}%"
            }

            # Feature importance via surrogate RandomForest on pseudo-labels
            try:
                rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
                temp_labels = np.where(pred == -1, 1, 0)
                rf.fit(X, temp_labels)
                imp = rf.feature_importances_
                # Plot top 20 features
                top_idx = np.argsort(imp)[-20:]
                top_feats = [X.columns[i] for i in top_idx]
                top_vals = imp[top_idx]
                buf = io.BytesIO()
                plt.figure(figsize=(12, 8))
                plt.barh(top_feats, top_vals, color='#2563eb')
                plt.title('Feature Importance (Surrogate RF on Anomaly Labels)')
                plt.tight_layout()
                plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
                plt.close()
                buf.seek(0)
                result['plots']['feature_importance'] = base64.b64encode(buf.getvalue()).decode()
            except Exception:
                pass
        else:
            result['anomaly'] = {'note': 'Not enough features/rows for anomaly detection'}
    except Exception as e:
        result['anomaly'] = {'error': f'Anomaly detection failed: {str(e)}'}

    return result

# Route for the homepage
@app.route('/')
def home():
    return render_template('index_unified.html')

# Route for PCAP analysis interface
@app.route('/pcap')
def pcap_analysis():
    return render_template('index_pcap.html')

# Route for modern UI
@app.route('/modern')
def modern():
    return render_template('index_modern.html')

# Route for PCAP file upload and processing
@app.route('/upload_pcap', methods=['POST'])
def upload_pcap_file():
    """Handle PCAP file upload and comprehensive analysis with improved error handling."""
    import logging
    import traceback as tb
    
    # Configure logging for this request
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    logger.info("Starting PCAP upload and analysis request...")
    
    try:
        # Check if advanced modules are available
        if not ADVANCED_MODULES_AVAILABLE:
            logger.error("Advanced PCAP analysis modules not available")
            return jsonify({
                'error': 'Advanced PCAP analysis modules not available. Please check server configuration.',
                'details': 'Required modules: pcap_parser, anomaly_detector, network_visualizer'
            }), 500

        # Validate file upload
        if 'file' not in request.files:
            logger.warning("No file part in request")
            return jsonify({'error': 'No file part in the request. Please select a PCAP file to upload.'}), 400

        file = request.files['file']
        if file.filename == '' or file.filename is None:
            logger.warning("No file selected for upload")
            return jsonify({'error': 'No file selected for upload. Please choose a PCAP file.'}), 400

        # Validate file extension
        allowed_extensions = ['.pcap', '.pcapng', '.cap']
        if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
            logger.warning(f"Invalid file type uploaded: {file.filename}")
            return jsonify({
                'error': f'Invalid file type: {file.filename}. Please upload a PCAP file with one of these extensions: {", ".join(allowed_extensions)}'
            }), 400

        # Create upload directory and save file
        upload_dir = app.config['UPLOAD_FOLDER']
        try:
            os.makedirs(upload_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create upload directory: {e}")
            return jsonify({'error': 'Failed to create upload directory on server.'}), 500
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{file.filename}"
        filepath = os.path.join(upload_dir, filename)
        
        try:
            file.save(filepath)
            logger.info(f"PCAP file saved successfully: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save uploaded file: {e}")
            return jsonify({'error': f'Failed to save uploaded file: {str(e)}'}), 500
            
        # Validate that file exists and has content
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            logger.error(f"Saved file is empty or doesn't exist: {filepath}")
            return jsonify({'error': 'Uploaded file is empty or could not be saved properly.'}), 400

        # Step 1: Analyze PCAP file
        try:
            logger.info("Step 1: Starting PCAP file parsing...")
            df, summary, suspicious_patterns = analyze_pcap_file(filepath, use_scapy=True)
            
            if df is None or df.empty:
                logger.error("PCAP parsing returned empty or no DataFrame")
                # Try fallback method
                try:
                    logger.info("Attempting fallback parsing with PyShark...")
                    df, summary, suspicious_patterns = analyze_pcap_file(filepath, use_scapy=False)
                except Exception as fallback_error:
                    logger.error(f"Fallback parsing also failed: {fallback_error}")
                    pass
                    
                if df is None or df.empty:
                    return jsonify({
                        'error': 'Failed to parse PCAP file or no packets were found.',
                        'details': 'The file might be corrupted, in an unsupported format, or contain no valid packets. Please verify the file is a valid PCAP/PCAPNG file.'
                    }), 400
            
            logger.info(f"Successfully parsed {len(df)} packets from PCAP file")
            logger.info(f"PCAP columns: {list(df.columns)}")
            
        except Exception as e:
            logger.error(f"Critical error during PCAP parsing: {str(e)}")
            logger.error(f"Traceback: {tb.format_exc()}")
            return jsonify({
                'error': f'Critical error occurred during PCAP file parsing: {str(e)}',
                'details': 'Please ensure the uploaded file is a valid PCAP/PCAPNG file and try again.'
            }), 500

        # Step 2: Anomaly Detection
        try:
            logger.info("Step 2: Initializing anomaly detection models...")
            
            # Validate data before anomaly detection
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) < 2:
                logger.warning(f"Limited numeric features found: {len(numeric_cols)}. Anomaly detection may be limited.")
            
            anomaly_detector = NetworkAnomalyDetector()
            logger.info("Training anomaly detection models...")
            anomaly_results = anomaly_detector.fit(df)
            
            if not anomaly_results:
                logger.warning("Anomaly detection returned empty results")
                anomaly_results = {'isolation_forest': {'anomalies': 0, 'anomaly_rate': 0.0}}
            
            logger.info("Anomaly detection training completed successfully")
            
        except Exception as e:
            logger.error(f"Error during anomaly detection: {str(e)}")
            logger.error(f"Traceback: {tb.format_exc()}")
            # Continue processing even if anomaly detection fails
            anomaly_results = {'error': str(e)}
            anomaly_detector = None
            logger.info("Continuing analysis without anomaly detection")

        # Step 3: Report Generation + CSV conversion + generic analysis
        viz_files = []  # Initialize in case visualization fails
        try:
            logger.info("Step 3: Generating analysis reports...")
            
            # Create reports directory
            report_dir = os.path.join(app.config['REPORT_FOLDER'], f"{timestamp}_{os.path.splitext(file.filename)[0]}")
            try:
                os.makedirs(report_dir, exist_ok=True)
                logger.info(f"Created report directory: {report_dir}")
            except Exception as dir_error:
                logger.error(f"Failed to create report directory: {dir_error}")
                report_dir = './reports'  # fallback to base reports dir
                os.makedirs(report_dir, exist_ok=True)
            
            # Generate anomaly report if detector is available
            anomaly_report = {}
            if anomaly_detector:
                try:
                    anomaly_report = anomaly_detector.generate_report(df)
                    logger.info("Generated anomaly detection report")
                except Exception as report_error:
                    logger.error(f"Failed to generate anomaly report: {report_error}")
                    anomaly_report = {'recommendations': []}
            
            # Generate visualizations
            try:
                if 'NetworkTrafficVisualizer' in globals():
                    visualizer = NetworkTrafficVisualizer()
                    viz_files = visualizer.create_comprehensive_report(
                        df,
                        anomaly_results=anomaly_results,
                        save_dir=report_dir
                    )
                    logger.info(f"Generated {len(viz_files)} visualization files")
                else:
                    logger.warning("NetworkTrafficVisualizer not available, creating basic visualization files")
                    viz_files = create_basic_visualizations(df, report_dir)
            except Exception as viz_error:
                logger.error(f"Visualization generation failed: {viz_error}")
                logger.info("Attempting to create basic visualizations as fallback")
                try:
                    viz_files = create_basic_visualizations(df, report_dir)
                except Exception as fallback_error:
                    logger.error(f"Fallback visualization also failed: {fallback_error}")
                    viz_files = []
            
            logger.info("Analysis reports generation completed")
            
        except Exception as e:
            logger.error(f"Error during report generation: {str(e)}")
            logger.error(f"Traceback: {tb.format_exc()}")
            # Continue processing - reports are non-critical
            viz_files = []
            anomaly_report = {'recommendations': []}

        # Auto-convert PCAP dataframe to CSV and run generic analysis in backend (invisible to user)
        generic_result = {}
        csv_save_path = None
        try:
            csv_dir = app.config['UPLOAD_FOLDER']
            os.makedirs(csv_dir, exist_ok=True)
            csv_save_path = os.path.join(csv_dir, f"{timestamp}_{os.path.splitext(file.filename)[0]}.csv")
            # Save a compact CSV for analysis
            df.to_csv(csv_save_path, index=False)
            # Run generic CSV analysis on the same dataframe to generate bar/heatmap/feature plots
            generic_result = analyze_generic_csv(df)
        except Exception as e:
            logger.warning(f"PCAP->CSV conversion or generic analysis failed: {e}")

        # Step 4: Prepare JSON response
        logger.info("Step 4: Preparing final analysis data...")
        
        # Helper function to convert numpy/pandas types to Python native types
        def convert_to_json_serializable(obj):
            """Convert numpy/pandas data types to JSON serializable types"""
            if isinstance(obj, (np.integer, np.int64, np.int32)):
                return int(obj)
            elif isinstance(obj, (np.floating, np.float64, np.float32)):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, pd.Series):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {key: convert_to_json_serializable(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_json_serializable(item) for item in obj]
            else:
                return obj
        
        # Convert summary to JSON serializable format
        safe_summary = convert_to_json_serializable(summary) if summary else {}
        
        # Convert anomaly results to JSON serializable format
        safe_anomaly_results = {}
        for model, result in anomaly_results.items():
            if isinstance(result, dict) and 'anomalies' in result:
                safe_anomaly_results[model] = {
                    'anomalies': int(result.get('anomalies', 0)),
                    'anomaly_rate': f"{float(result.get('anomaly_rate', 0))*100:.2f}%"
                }

        # Derive model accuracy surrogate from ensemble agreement if available
        model_agreement = None
        try:
            model_agreement = float(anomaly_results.get('ensemble', {}).get('model_agreement', None))
        except Exception:
            model_agreement = None

        accuracy_text = f"{model_agreement*100:.2f}%" if model_agreement is not None else 'N/A'

        # Build security alerts from suspicious patterns and anomaly detections
        security_alerts = []
        try:
            sec_summary = safe_summary.get('security_analysis', {})
            suspicious_count = int(sec_summary.get('suspicious_packets', 0))
            if suspicious_count > 0:
                security_alerts.append({
                    'severity': 'high' if suspicious_count > 10 else 'medium',
                    'title': 'Suspicious payload activity detected',
                    'details': f"Detected {suspicious_count} packets with suspicious payload patterns.",
                })
            attack_patterns = sec_summary.get('attack_patterns', {})
            if isinstance(attack_patterns, dict):
                top_patterns = sorted(attack_patterns.items(), key=lambda x: x[1], reverse=True)[:5]
                for patt, count in top_patterns:
                    security_alerts.append({
                        'severity': 'medium',
                        'title': 'Attack pattern observed',
                        'details': f"Pattern {patt} seen {count} times.",
                    })
        except Exception:
            pass

        # If anomalies present, raise an alert
        total_anomalies_detected = sum(v.get('anomalies', 0) for v in safe_anomaly_results.values())
        if total_anomalies_detected > 0:
            security_alerts.insert(0, {
                'severity': 'high' if total_anomalies_detected > 50 else 'medium',
                'title': 'Anomalous traffic detected',
                'details': f"Detected {total_anomalies_detected} anomalous samples across models.",
            })
        
        response_data = {
            'success': True,
            'filename': str(file.filename),
            'total_packets': int(len(df)),
            'analysis_summary': safe_summary,
            'anomaly_results': safe_anomaly_results,
            'data_preview': df.head(10).to_html(classes='table table-striped', table_id='pcap-preview'),
            'feature_count': int(len(df.columns)),
            'report_files': [str(f) for f in viz_files],
            'recommendations': [str(rec) for rec in anomaly_report.get('recommendations', [])],
            'accuracy': accuracy_text,
            'security_alerts': security_alerts,
            'export_basename': f"{timestamp}_{os.path.splitext(file.filename)[0]}",
            'converted_csv_path': csv_save_path,
            'column_sums': (generic_result.get('derived', {}) or {}).get('numeric_sums', {}),
            'heatmap': (generic_result.get('plots', {}) or {}).get('correlation_heatmap', ''),
            'importance_plot': (generic_result.get('plots', {}) or {}).get('feature_importance', ''),
            'bar_plot': (generic_result.get('plots', {}) or {}).get('numeric_distributions') or (generic_result.get('plots', {}) or {}).get('missing_bar', ''),
            'data_profile': generic_result.get('data_profile', {})
        }

        # Step 5: Generate plots for the dashboard
        logger.info("Step 5: Generating dashboard plots...")
        try:
            if anomaly_detector is not None:
                importance_data = anomaly_detector.get_feature_importance(df)
                if importance_data and 'isolation_forest' in importance_data:
                    importance_plot = io.BytesIO()
                    plt.figure(figsize=(12, 8))
                    importance = importance_data['isolation_forest']
                    features = anomaly_detector.feature_columns[:len(importance)]
                    top_indices = np.argsort(importance)[-15:]
                    top_features = [features[i] for i in top_indices]
                    top_importance = importance[top_indices]
                    plt.barh(top_features, top_importance, color='skyblue')
                    plt.title('Top Feature Importance for Anomaly Detection', fontsize=14, fontweight='bold')
                    plt.xlabel('Importance Score')
                    plt.tight_layout()
                    plt.savefig(importance_plot, format='png', dpi=150, bbox_inches='tight')
                    plt.close()
                    importance_plot.seek(0)
                    response_data['feature_importance'] = base64.b64encode(importance_plot.getvalue()).decode()
                    logger.info("✓ Feature importance plot generated")
                else:
                    logger.warning("No feature importance data available")
            else:
                logger.warning("Anomaly detector not available for feature importance plot")
        except Exception as e:
            logger.warning(f"Could not generate feature importance plot: {e}")

        try:
            if 'protocol' in df.columns:
                protocol_plot = io.BytesIO()
                plt.figure(figsize=(10, 6))
                protocol_counts = df['protocol'].value_counts()
                colors = ['#ff9999','#66b3ff','#99ff99','#ffcc99','#c2c2f0']
                protocol_counts.plot(kind='pie', autopct='%1.1f%%', colors=colors[:len(protocol_counts)])
                plt.title('Protocol Distribution', fontsize=14, fontweight='bold')
                plt.ylabel('')
                plt.tight_layout()
                plt.savefig(protocol_plot, format='png', dpi=150, bbox_inches='tight')
                plt.close()
                protocol_plot.seek(0)
                response_data['protocol_distribution'] = base64.b64encode(protocol_plot.getvalue()).decode()
        except Exception as e:
            print(f"Warning: Could not generate protocol distribution plot. {e}")

        try:
            if 'timestamp' in df.columns or 'datetime' in df.columns:
                df['datetime'] = pd.to_datetime(df.get('timestamp', df.get('datetime')), unit='s' if 'timestamp' in df.columns else None)
                timeline_plot = io.BytesIO()
                plt.figure(figsize=(12, 6))
                hourly_traffic = df.groupby(df['datetime'].dt.floor('H')).size()
                plt.plot(hourly_traffic.index, hourly_traffic.values, marker='o', linewidth=2, markersize=4)
                plt.title('Network Traffic Timeline (Packets per Hour)', fontsize=14, fontweight='bold')
                plt.xlabel('Time')
                plt.ylabel('Packet Count')
                plt.xticks(rotation=45)
                plt.grid(True, alpha=0.3)
                plt.tight_layout()
                plt.savefig(timeline_plot, format='png', dpi=150, bbox_inches='tight')
                plt.close()
                timeline_plot.seek(0)
                response_data['traffic_timeline'] = base64.b64encode(timeline_plot.getvalue()).decode()
        except Exception as e:
            print(f"Warning: Could not generate traffic timeline plot. {e}")

        # Store data for export functionality
        export_csv.last_data = df
        export_json.last_results = response_data
        export_pdf.last_results = response_data
        
        print("PCAP analysis completed successfully.")
        return jsonify(response_data)

    except Exception as e:
        print(f"An unexpected error occurred in upload_pcap_file: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'An unexpected and critical error occurred: {str(e)}'}), 500

# Route to handle CSV file upload and data processing (original functionality)
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Load the dataset
        data = pd.read_csv(file)
        print(f"Dataset loaded successfully. Shape: {data.shape}")
        print(f"Columns: {list(data.columns)}")
        print(f"First few rows:\n{data.head()}")

        # Check if this is a network intrusion detection dataset or raw network traffic
        nids_columns = ['num_failed_logins', 'hot', 'num_access_files', 'attack_type', 'label']
        traffic_columns = ['Time', 'Source', 'No.', 'Destination', 'Protocol', 'Length', 'Info']
        
        has_nids_format = all(col in data.columns for col in nids_columns)
        has_traffic_format = all(col in data.columns for col in traffic_columns)
        
        if has_nids_format:
            print("Detected Network Intrusion Detection Dataset format")
            # Feature columns and target for NIDS data
            features = ['num_failed_logins', 'hot', 'num_access_files', 'attack_type']
            target = 'label'
            
            # Extract features and target
            X = data[features].copy()
            y = data[target].copy()
            
        elif has_traffic_format:
            print("Detected raw network traffic data format")
            # Create features from raw traffic data
            protocol_counts = data['Protocol'].value_counts().to_dict()
            print(f"Protocol distribution: {protocol_counts}")
            
            # Create comprehensive features from the traffic data
            feature_data = pd.DataFrame()
            
            # Basic packet features
            feature_data['packet_length'] = pd.to_numeric(data['Length'], errors='coerce').fillna(0)
            feature_data['protocol_encoded'] = pd.Categorical(data['Protocol']).codes
            feature_data['time_delta'] = data['Time'].diff().fillna(0)
            
            # Network behavior features
            feature_data['is_broadcast'] = (data['Destination'].str.contains('Broadcast|255.255|ff:ff:ff:ff:ff:ff', case=False, na=False)).astype(int)
            
            # Source and destination frequency (communication patterns)
            source_counts = data['Source'].value_counts()
            dest_counts = data['Destination'].value_counts()
            feature_data['source_frequency'] = data['Source'].map(source_counts)
            feature_data['dest_frequency'] = data['Destination'].map(dest_counts)
            
            # Protocol diversity indicators
            protocol_variety = data.groupby('Source')['Protocol'].nunique()
            feature_data['protocol_variety'] = data['Source'].map(protocol_variety).fillna(1)
            
            # Info field analysis (if available)
            if 'Info' in data.columns:
                feature_data['info_length'] = data['Info'].astype(str).str.len()
                feature_data['has_error'] = data['Info'].str.contains('error|fail|timeout|refused', case=False, na=False).astype(int)
            else:
                feature_data['info_length'] = 0
                feature_data['has_error'] = 0
            
            # Create anomaly labels based on multiple criteria
            length_threshold = feature_data['packet_length'].quantile(0.95)
            freq_threshold = feature_data['source_frequency'].quantile(0.90)
            
            # Label as anomaly if: unusual packet length OR high frequency communication OR has error indicators
            y = ((feature_data['packet_length'] > length_threshold) | 
                 (feature_data['source_frequency'] > freq_threshold) |
                 (feature_data['has_error'] > 0)).astype(int)
            
            # Select all created features
            features = ['packet_length', 'protocol_encoded', 'time_delta', 'is_broadcast', 
                       'source_frequency', 'dest_frequency', 'protocol_variety', 'info_length', 'has_error']
            X = feature_data[features].copy()
            
            print(f"Created {len(features)} features from network traffic data")
            print(f"Anomaly detection: {y.sum()} anomalies out of {len(y)} packets ({y.mean()*100:.2f}%)")
            
        else:
            # Generic analysis for any CSV schema
            print("Running generic CSV analysis pipeline...")
            generic = analyze_generic_csv(data)

            # Build response compatible with existing UI keys
            response = {
                'data_preview': generic.get('preview', ''),
                'column_sums': generic.get('derived', {}).get('numeric_sums', {}),
                'bar_plot': generic.get('plots', {}).get('numeric_distributions') or generic.get('plots', {}).get('missing_bar', ''),
                'heatmap': generic.get('plots', {}).get('correlation_heatmap', ''),
                'importance_plot': generic.get('plots', {}).get('feature_importance', ''),
                'data_profile': generic.get('data_profile', {}),
                'anomaly_summary': generic.get('anomaly', {})
            }

            # Derived totals and security alerts for CSV
            try:
                total_rows = int(response['data_profile'].get('shape', {}).get('rows', len(data)))
            except Exception:
                total_rows = int(len(data))
            anomaly_info = response.get('anomaly_summary', {})
            anomalies_count = int(anomaly_info.get('anomalies', 0)) if isinstance(anomaly_info, dict) else 0
            security_alerts = []
            if anomalies_count > 0:
                security_alerts.append({
                    'severity': 'medium' if anomalies_count < 50 else 'high',
                    'title': 'Anomalies detected in CSV analysis',
                    'details': f'Detected {anomalies_count} anomalous rows using {anomaly_info.get("model", "Anomaly Model")}.',
                })
            response.update({
                'total_rows': total_rows,
                'csv_anomalies': anomalies_count,
                'threats_detected': anomalies_count,
                'security_alerts': security_alerts,
                'export_basename': datetime.now().strftime('%Y%m%d_%H%M%S') + '_csv'
            })
            
            # Store data for export functionality
            export_csv.last_data = data
            export_json.last_results = response
            export_pdf.last_results = response
            
            return jsonify(response)
        
        # Handle categorical columns if they exist
        categorical_columns = X.select_dtypes(include=['object', 'category']).columns
        if len(categorical_columns) > 0:
            print(f"Encoding categorical columns: {list(categorical_columns)}")
            le = LabelEncoder()
            for col in categorical_columns:
                X[col] = le.fit_transform(X[col].astype(str))
        
        print(f"Features shape: {X.shape}")
        print(f"Target shape: {y.shape}")

        # Calculate the sum of features (only numeric columns)
        numeric_X = X.select_dtypes(include=[float, int])
        column_sums = numeric_X.sum().to_dict()
        print(f"Column sums: {column_sums}")

        # Bar plot for feature sums
        bar_plot = io.BytesIO()
        plt.figure(figsize=(8, 5))
        pd.Series(column_sums).plot(kind='bar', color=['blue', 'green', 'orange', 'red'])
        plt.title('Sum of Features')
        plt.ylabel('Sum')
        plt.xlabel('Feature')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(bar_plot, format='png')
        plt.close()
        bar_plot.seek(0)
        bar_plot_base64 = base64.b64encode(bar_plot.getvalue()).decode()

        # Heatmap for correlations (only numeric columns)
        heatmap = io.BytesIO()
        plt.figure(figsize=(10, 6))
        correlation_matrix = X.select_dtypes(include=[float, int]).corr()
        sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt=".2f")
        plt.title('Feature Correlation Heatmap')
        plt.tight_layout()
        plt.savefig(heatmap, format='png')
        plt.close()
        heatmap.seek(0)
        heatmap_base64 = base64.b64encode(heatmap.getvalue()).decode()

        # Train-Test Split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        print(f"Training set shape: {X_train.shape}, Test set shape: {X_test.shape}")

        # Train the RandomForestClassifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        print("Model training completed")

        # Feature importance plot
        importance_plot = io.BytesIO()
        feature_importances = pd.Series(model.feature_importances_, index=features)
        feature_importances.sort_values().plot(kind='barh', color='teal')
        plt.title('Feature Importance')
        plt.xlabel('Importance')
        plt.tight_layout()
        plt.savefig(importance_plot, format='png')
        plt.close()
        importance_plot.seek(0)
        importance_plot_base64 = base64.b64encode(importance_plot.getvalue()).decode()

        # Evaluate the model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model accuracy: {accuracy * 100:.2f}%")

        # Ensure model directory exists
        os.makedirs(app.config['MODEL_FOLDER'], exist_ok=True)
        
        # Save the model
        joblib.dump(model, os.path.join(app.config['MODEL_FOLDER'], 'random_forest_model.pkl'))
        print("Model saved successfully")

        # Store data for export functionality
        anomalies_count = int(y.sum()) if hasattr(y, 'sum') else int(np.sum(y))
        security_alerts = []
        if anomalies_count > 0:
            security_alerts.append({
                'severity': 'medium' if anomalies_count < 50 else 'high',
                'title': 'Anomalies detected in CSV traffic dataset',
                'details': f'{anomalies_count} rows flagged as anomalous by heuristic labeling.',
            })

        final_results = {
            'accuracy': f'{accuracy * 100:.2f}%',
            'bar_plot': bar_plot_base64,
            'heatmap': heatmap_base64,
            'importance_plot': importance_plot_base64,
            'data_preview': data.head().to_html(classes='table table-bordered', index=False),
            'column_sums': column_sums,
            'total_rows': int(len(data)),
            'csv_anomalies': anomalies_count,
            'threats_detected': anomalies_count,
            'security_alerts': security_alerts,
            'export_basename': datetime.now().strftime('%Y%m%d_%H%M%S') + '_csv'
        }
        export_csv.last_data = data
        export_json.last_results = final_results
        export_pdf.last_results = final_results
        
        # Return results to the UI
        return jsonify(final_results)
    
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

# Route for exporting CSV data
@app.route('/export/csv', methods=['GET'])
def export_csv():
    """Export the analyzed data as CSV"""
    try:
        # Check if we have session data or need to return error
        if not hasattr(export_csv, 'last_data') or export_csv.last_data is None:
            return jsonify({'error': 'No data available for export. Please upload and analyze a file first.'}), 400
        
        df = export_csv.last_data
        
        # Create a CSV in memory
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        # Create response
        basename = None
        try:
            basename = getattr(export_json, 'last_results', {}).get('export_basename') if hasattr(export_json, 'last_results') else None
        except Exception:
            basename = None
        filename = f"{basename or datetime.now().strftime('%Y%m%d_%H%M%S')}_export.csv"
        return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={filename}'})
    except Exception as e:
        logger.error(f"CSV export failed: {e}")
        return jsonify({'error': f'CSV export failed: {str(e)}'}), 500


# Route for exporting JSON report
@app.route('/export/json', methods=['GET'])
def export_json():
    """Export the analysis results as JSON"""
    try:
        if not hasattr(export_json, 'last_results') or export_json.last_results is None:
            return jsonify({'error': 'No analysis results available for export. Please upload and analyze a file first.'}), 400
        
        results = export_json.last_results
        
        # Create response
        basename = results.get('export_basename') if isinstance(results, dict) else None
        filename = f"{basename or datetime.now().strftime('%Y%m%d_%H%M%S')}_report.json"
        return Response(json.dumps(results, indent=2, default=str), mimetype='application/json', headers={'Content-Disposition': f'attachment; filename={filename}'})
    except Exception as e:
        logger.error(f"JSON export failed: {e}")
        return jsonify({'error': f'JSON export failed: {str(e)}'}), 500


# Route for exporting PDF report
@app.route('/export/pdf', methods=['GET'])
def export_pdf():
    """Export analysis results as PDF report"""
    try:
        if not hasattr(export_pdf, 'last_results') or export_pdf.last_results is None:
            return jsonify({'error': 'No analysis results available for export. Please upload and analyze a file first.'}), 400
        
        results = export_pdf.last_results
        basename = results.get('export_basename') if isinstance(results, dict) else None
        
        # Import Response at the function level to ensure it's available
        from flask import Response

        # Prefer HTML-based PDF with embedded base64 charts when WeasyPrint is available
        try:
            try:
                import weasyprint
            except Exception as imp_err:
                raise RuntimeError(f"WeasyPrint unavailable: {imp_err}")

            html_template = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>Network Analysis Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; }
                        h1 { color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }
                        h2 { color: #1e40af; margin-top: 30px; }
                        .metric { background: #f8fafc; padding: 15px; margin: 10px 0; border-left: 4px solid #2563eb; }
                        .metric-value { font-size: 24px; font-weight: bold; color: #1e40af; }
                        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        .chart-placeholder { background: #f8fafc; padding: 40px; text-align: center; margin: 20px 0; border: 2px dashed #cbd5e1; }
                    </style>
                </head>
                <body>
                    <h1>Network Traffic Analysis Report</h1>
                    <p>Generated on: {{ timestamp }}</p>
                    
                    {% if results.get('total_packets') %}
                    <h2>PCAP Analysis Summary</h2>
                    <div class="metric">
                        <div class="metric-value">{{ results.total_packets }}</div>
                        <div>Total Packets Analyzed</div>
                    </div>
                    {% endif %}
                    
                    {% if results.get('accuracy') %}
                    <div class="metric">
                        <div class="metric-value">{{ results.accuracy }}</div>
                        <div>Model Accuracy</div>
                    </div>
                    {% endif %}
                    
                    {% if results.get('anomaly_results') %}
                    <h2>Anomaly Detection Results</h2>
                    {% for model, result in results.anomaly_results.items() %}
                    <div class="metric">
                        <div class="metric-value">{{ result.get('anomalies', 'N/A') }}</div>
                        <div>{{ model.replace('_', ' ').title() }} - Anomalies Detected</div>
                    </div>
                    {% endfor %}
                    {% endif %}
                    {% if results.get('csv_anomalies') is not none %}
                    <div class="metric">
                        <div class="metric-value">{{ results.csv_anomalies }}</div>
                        <div>CSV Anomalies Detected</div>
                    </div>
                    {% endif %}
                    
                    {% if results.get('security_alerts') %}
                    <h2>Security Alerts</h2>
                    <ul>
                    {% for a in results.security_alerts[:10] %}
                        <li>[{{ a.get('severity','info')|upper }}] {{ a.get('title','Alert') }} - {{ a.get('details','') }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}

                    {% if results.get('recommendations') %}
                    <h2>Security Recommendations</h2>
                    <ul>
                    {% for rec in results.recommendations[:10] %}
                        <li>{{ rec }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                    
                    <h2>Analysis Charts</h2>
                    {% if results.get('bar_plot') %}
                        <h3>Feature Distributions</h3>
                        <img src="data:image/png;base64,{{ results.bar_plot }}" style="width:100%; max-width:800px;"/>
                    {% endif %}
                    {% if results.get('heatmap') %}
                        <h3>Correlation Heatmap</h3>
                        <img src="data:image/png;base64,{{ results.heatmap }}" style="width:100%; max-width:800px;"/>
                    {% endif %}
                    {% if results.get('importance_plot') %}
                        <h3>Feature Importance</h3>
                        <img src="data:image/png;base64,{{ results.importance_plot }}" style="width:100%; max-width:800px;"/>
                    {% endif %}
                    {% if results.get('protocol_distribution') %}
                        <h3>Protocol Distribution</h3>
                        <img src="data:image/png;base64,{{ results.protocol_distribution }}" style="width:100%; max-width:800px;"/>
                    {% endif %}
                    {% if results.get('traffic_timeline') %}
                        <h3>Traffic Timeline</h3>
                        <img src="data:image/png;base64,{{ results.traffic_timeline }}" style="width:100%; max-width:800px;"/>
                    {% endif %}
                    
                    <h2>Data Summary</h2>
                    {% if results.get('data_profile') %}
                    <table>
                        <tr><th>Metric</th><th>Value</th></tr>
                        {% if results.data_profile.get('shape') %}
                        <tr><td>Rows</td><td>{{ results.data_profile.shape.rows }}</td></tr>
                        <tr><td>Columns</td><td>{{ results.data_profile.shape.cols }}</td></tr>
                        {% endif %}
                        {% if results.data_profile.get('memory_mb') %}
                        <tr><td>Memory Usage</td><td>{{ "%.2f"|format(results.data_profile.memory_mb) }} MB</td></tr>
                        {% endif %}
                    </table>
                    {% else %}
                    <p>Data profile unavailable for this analysis.</p>
                    {% endif %}
                </body>
                </html>
                """
            
            html_content = render_template_string(
                html_template,
                results=results,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )

            try:
                pdf_buffer = io.BytesIO()
                weasyprint.HTML(string=html_content).write_pdf(pdf_buffer)
                pdf_buffer.seek(0)

                filename = f"{basename or datetime.now().strftime('%Y%m%d_%H%M%S')}_report.pdf"
                return Response(pdf_buffer.getvalue(), mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename={filename}'})
            except Exception as we_err:
                logger.warning(f"WeasyPrint failed, falling back to ReportLab: {we_err}")

        except Exception as e:
            # Fall back to ReportLab-based PDF for any WeasyPrint-related error
            logger.info(f"Skipping WeasyPrint path due to: {e}")

        # ReportLab generation path
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
        except ImportError:
            # Final fallback: Text report
            report_lines = [
                "NETWORK TRAFFIC ANALYSIS REPORT",
                "=" * 40,
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
            ]

            if results.get('total_packets'):
                report_lines.extend([
                    "PCAP ANALYSIS SUMMARY:",
                    f"Total Packets: {results['total_packets']}",
                    f"Features: {results.get('feature_count', 'N/A')}",
                    ""
                ])

            if results.get('accuracy'):
                report_lines.extend([
                    "MODEL PERFORMANCE:",
                    f"Accuracy: {results['accuracy']}",
                    ""
                ])

            if results.get('anomaly_results'):
                report_lines.append("ANOMALY DETECTION:")
                for model, result in results['anomaly_results'].items():
                    report_lines.append(f"  {model.replace('_', ' ').title()}: {result.get('anomalies', 'N/A')} anomalies")
                report_lines.append("")

            if results.get('recommendations'):
                report_lines.append("SECURITY RECOMMENDATIONS:")
                for i, rec in enumerate(results['recommendations'][:10], 1):
                    report_lines.append(f"  {i}. {rec}")
                report_lines.append("")

            return Response(
                "\n".join(report_lines),
                mimetype='text/plain',
                headers={'Content-Disposition': 'attachment; filename=network_analysis_report.txt'}
            )
        
        # If reportlab is available, create a proper PDF with embedded charts
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=1*inch)
        styles = getSampleStyleSheet()
        story = []
        from reportlab.lib.utils import ImageReader

        def _image_from_base64(data_b64: str, width, height):
            try:
                image_bytes = base64.b64decode(data_b64)
                reader = ImageReader(io.BytesIO(image_bytes))
                return Image(reader, width=width, height=height)
            except Exception:
                return None
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#2563eb'),
            spaceAfter=30
        )
        story.append(Paragraph("Network Traffic Analysis Report", title_style))
        story.append(Spacer(1, 12))
        
        # Timestamp
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Summary metrics
        if results.get('total_packets'):
            story.append(Paragraph("Analysis Summary", styles['Heading2']))
            data = [
                ['Metric', 'Value'],
                ['Total Packets', str(results.get('total_packets', 'N/A'))],
                ['Features', str(results.get('feature_count', 'N/A'))],
                ['Model Accuracy', str(results.get('accuracy', 'N/A'))]
            ]
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8fafc')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 20))
        
        # AI-generated narrative sections
        story.append(Paragraph("Overview", styles['Heading2']))
        overview_lines = []
        if results.get('total_packets'):
            overview_lines.append(f"Analyzed {results.get('total_packets')} packets with {results.get('feature_count', 'N/A')} derived features.")
        if results.get('total_rows'):
            overview_lines.append(f"Processed CSV with {results.get('total_rows')} rows.")
        if results.get('accuracy'):
            overview_lines.append(f"Model/ensemble confidence reported as {results.get('accuracy')}.")
        story.append(Paragraph(" ".join(overview_lines) or "This report summarizes the uploaded dataset and detected behaviors.", styles['Normal']))
        story.append(Spacer(1, 12))

        # Detected Threats / Security Alerts
        alerts = results.get('security_alerts') or []
        story.append(Paragraph("Detected Threats & Security Alerts", styles['Heading2']))
        if alerts:
            for a in alerts[:10]:
                story.append(Paragraph(f"- [{a.get('severity', 'info').upper()}] {a.get('title', 'Alert')}: {a.get('details', '')}", styles['Normal']))
        else:
            story.append(Paragraph("No explicit security alerts were generated.", styles['Normal']))
        story.append(Spacer(1, 12))

        # Anomalies Section
        story.append(Paragraph("Anomalies", styles['Heading2']))
        if results.get('anomaly_results'):
            total_anoms = 0
            for model, r in results['anomaly_results'].items():
                if isinstance(r, dict):
                    total_anoms += int(r.get('anomalies', 0))
            story.append(Paragraph(f"Detected {total_anoms} anomalous samples across available detectors.", styles['Normal']))
        elif results.get('csv_anomalies') is not None:
            story.append(Paragraph(f"Detected {results.get('csv_anomalies', 0)} anomalous rows in CSV analysis.", styles['Normal']))
        else:
            story.append(Paragraph("No anomaly summary available.", styles['Normal']))
        story.append(Spacer(1, 12))

        # Recommendations Section
        story.append(Paragraph("Recommendations", styles['Heading2']))
        recs = results.get('recommendations') or []
        if recs:
            for i, rec in enumerate(recs[:10], 1):
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        else:
            story.append(Paragraph("No specific recommendations generated.", styles['Normal']))
        story.append(Spacer(1, 20))

        # Additional detailed narrative from available summaries
        analysis_summary = results.get('analysis_summary') or {}
        if analysis_summary:
            # Protocol summary
            proto = (analysis_summary.get('basic_features') or {}).get('protocol_distribution') or {}
            if proto:
                story.append(Paragraph("Protocol Summary", styles['Heading2']))
                top = sorted(proto.items(), key=lambda x: x[1], reverse=True)[:5]
                proto_items = ", ".join([f"{k}: {v}" for k, v in top])
                story.append(Paragraph(f"Top protocols by packet count: {proto_items}.", styles['Normal']))
                story.append(Spacer(1, 12))

            # DNS analysis
            dns_info = analysis_summary.get('dns_analysis') or {}
            if dns_info:
                story.append(Paragraph("DNS Analysis", styles['Heading2']))
                story.append(Paragraph(
                    f"Observed {dns_info.get('total_queries', 0)} DNS queries across {dns_info.get('unique_domains', 0)} unique domains.",
                    styles['Normal']
                ))
                story.append(Spacer(1, 12))

            # HTTP analysis
            http_info = analysis_summary.get('http_analysis') or {}
            if http_info:
                story.append(Paragraph("HTTP Analysis", styles['Heading2']))
                story.append(Paragraph(
                    f"Captured {http_info.get('total_requests', 0)} HTTP requests to {http_info.get('unique_hosts', 0)} hosts.",
                    styles['Normal']
                ))
                story.append(Spacer(1, 12))

            # Security analysis
            sec_info = analysis_summary.get('security_analysis') or {}
            if sec_info:
                story.append(Paragraph("Security Analysis", styles['Heading2']))
                story.append(Paragraph(
                    f"Flagged {sec_info.get('suspicious_packets', 0)} suspicious packets and {sec_info.get('high_risk_flows', 0)} high-risk flows.",
                    styles['Normal']
                ))
                patt = sec_info.get('attack_patterns') or {}
                if isinstance(patt, dict) and patt:
                    top_p = sorted(patt.items(), key=lambda x: x[1], reverse=True)[:5]
                    patt_items = ", ".join([f"{k}: {v}" for k, v in top_p])
                    story.append(Paragraph(f"Top detected attack patterns: {patt_items}.", styles['Normal']))
                story.append(Spacer(1, 12))

        # Embed charts as images (bar plot and others)
        chart_added = False

        # Bar plot from generic analysis
        if results.get('bar_plot'):
            story.append(Paragraph("Feature Distributions", styles['Heading2']))
            img = _image_from_base64(results['bar_plot'], 6*inch, 4*inch)
            if img:
                story.append(img)
                story.append(Spacer(1, 12))
                chart_added = True
        
        # Add Feature Importance Chart
        if results.get('feature_importance') or results.get('importance_plot'):
            story.append(Paragraph("Feature Importance Analysis", styles['Heading2']))
            
            chart_data = results.get('feature_importance') or results.get('importance_plot')
            if chart_data:
                img = _image_from_base64(chart_data, 6*inch, 4*inch)
                if img:
                    story.append(img)
                    story.append(Spacer(1, 12))
                    chart_added = True
        
        # Add Protocol Distribution Chart
        if results.get('protocol_distribution'):
            story.append(Paragraph("Protocol Distribution", styles['Heading2']))
            
            img = _image_from_base64(results['protocol_distribution'], 6*inch, 4*inch)
            if img:
                story.append(img)
                story.append(Spacer(1, 12))
                chart_added = True
        
        # Add Traffic Timeline Chart
        if results.get('traffic_timeline'):
            story.append(Paragraph("Traffic Timeline", styles['Heading2']))
            
            img = _image_from_base64(results['traffic_timeline'], 6*inch, 3*inch)
            if img:
                story.append(img)
                story.append(Spacer(1, 12))
                chart_added = True
        
        # Add Correlation Heatmap
        if results.get('heatmap'):
            story.append(Paragraph("Correlation Analysis", styles['Heading2']))
            
            img = _image_from_base64(results['heatmap'], 6*inch, 4*inch)
            if img:
                story.append(img)
                story.append(Spacer(1, 12))
                chart_added = True
        
        if not chart_added:
            story.append(Paragraph("No charts available for embedding", styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Anomaly results
        if results.get('anomaly_results'):
            story.append(Paragraph("Anomaly Detection Results", styles['Heading2']))
            for model, result in results['anomaly_results'].items():
                model_name = model.replace('_', ' ').title()
                story.append(Paragraph(f"{model_name}: {result.get('anomalies', 'N/A')} anomalies detected", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Recommendations
        if results.get('recommendations'):
            story.append(Paragraph("Security Recommendations", styles['Heading2']))
            for i, rec in enumerate(results['recommendations'][:10], 1):
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        filename = f"{basename or datetime.now().strftime('%Y%m%d_%H%M%S')}_report.pdf"
        return Response(buffer.getvalue(), mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename={filename}'})
        
    except Exception as e:
        logger.error(f"PDF export failed after all fallbacks: {e}")
        return jsonify({'error': f'PDF export failed. Please check server logs.'}), 500


if __name__ == '__main__':
    app.run(debug=True)
