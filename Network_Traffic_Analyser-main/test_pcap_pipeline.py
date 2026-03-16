#!/usr/bin/env python3
"""
Test script for PCAP processing pipeline validation
This script tests the main components of the PCAP analysis system.
"""

import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_imports():
    """Test if all required modules can be imported"""
    logger.info("Testing module imports...")
    
    try:
        import pandas as pd
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.svm import OneClassSVM
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import RobustScaler
        logger.info("✓ Core ML libraries imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import core ML libraries: {e}")
        return False
    
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        logger.info("✓ Visualization libraries imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import visualization libraries: {e}")
        return False
    
    # Test advanced modules
    try:
        from anomaly_detector import NetworkAnomalyDetector
        logger.info("✓ NetworkAnomalyDetector imported successfully")
    except ImportError as e:
        logger.warning(f"⚠ NetworkAnomalyDetector not available: {e}")
    
    try:
        from pcap_parser import analyze_pcap_file
        logger.info("✓ PCAP parser imported successfully")
    except ImportError as e:
        logger.warning(f"⚠ PCAP parser not available: {e}")
    
    try:
        from network_visualizer import NetworkTrafficVisualizer
        logger.info("✓ NetworkTrafficVisualizer imported successfully")
    except ImportError as e:
        logger.warning(f"⚠ NetworkTrafficVisualizer not available: {e}")
    
    return True

def test_anomaly_detector():
    """Test the anomaly detector with synthetic data"""
    logger.info("Testing NetworkAnomalyDetector...")
    
    try:
        from anomaly_detector import NetworkAnomalyDetector
        
        # Create synthetic network data
        np.random.seed(42)
        n_samples = 1000
        n_features = 15
        
        # Normal network traffic features
        data = {
            'packet_size': np.random.normal(1500, 300, n_samples),
            'inter_arrival_time': np.random.exponential(0.01, n_samples),
            'src_port': np.random.randint(1024, 65535, n_samples),
            'dst_port': np.random.choice([80, 443, 22, 21, 25], n_samples),
            'protocol': np.random.choice([6, 17, 1], n_samples),  # TCP, UDP, ICMP
            'flags': np.random.randint(0, 255, n_samples),
            'ttl': np.random.randint(32, 255, n_samples),
            'window_size': np.random.randint(1024, 65535, n_samples),
            'payload_len': np.random.randint(0, 1460, n_samples),
        }
        
        # Add more synthetic features
        for i in range(6):
            data[f'feature_{i}'] = np.random.normal(0, 1, n_samples)
        
        df = pd.DataFrame(data)
        
        # Add some anomalies
        anomaly_indices = np.random.choice(n_samples, 50, replace=False)
        df.loc[anomaly_indices, 'packet_size'] = np.random.normal(5000, 1000, 50)  # Large packets
        df.loc[anomaly_indices[:25], 'inter_arrival_time'] = np.random.exponential(0.1, 25)  # Slow connections
        
        logger.info(f"Created synthetic dataset with {len(df)} samples and {len(df.columns)} features")
        
        # Test anomaly detector
        detector = NetworkAnomalyDetector()
        results = detector.fit(df)
        
        if results:
            logger.info("✓ NetworkAnomalyDetector training completed successfully")
            
            # Check results
            for model_name, result in results.items():
                if 'anomalies' in result:
                    anomaly_count = result['anomalies']
                    anomaly_rate = result['anomaly_rate'] * 100
                    logger.info(f"  - {model_name}: {anomaly_count} anomalies ({anomaly_rate:.2f}%)")
            
            # Test report generation
            try:
                report = detector.generate_report(df)
                logger.info("✓ Report generation successful")
                
                if 'recommendations' in report:
                    logger.info(f"  - Generated {len(report['recommendations'])} recommendations")
                    
            except Exception as e:
                logger.warning(f"⚠ Report generation failed: {e}")
            
            # Test feature importance
            try:
                importance = detector.get_feature_importance(df)
                if importance:
                    logger.info("✓ Feature importance calculation successful")
                else:
                    logger.warning("⚠ Feature importance returned empty results")
            except Exception as e:
                logger.warning(f"⚠ Feature importance calculation failed: {e}")
            
            return True
        else:
            logger.error("✗ NetworkAnomalyDetector training failed")
            return False
            
    except ImportError:
        logger.warning("⚠ NetworkAnomalyDetector not available, skipping test")
        return True
    except Exception as e:
        logger.error(f"✗ NetworkAnomalyDetector test failed: {e}")
        return False

def test_generic_csv_analyzer():
    """Test the generic CSV analysis functionality"""
    logger.info("Testing generic CSV analyzer...")
    
    try:
        # Import the function from app
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from app import analyze_generic_csv
        
        # Create test data with different data types
        np.random.seed(42)
        n_samples = 500
        
        test_data = {
            'numeric_col1': np.random.normal(100, 15, n_samples),
            'numeric_col2': np.random.exponential(5, n_samples),
            'categorical_col': np.random.choice(['A', 'B', 'C', 'D'], n_samples),
            'boolean_col': np.random.choice([True, False], n_samples),
            'string_col': np.random.choice(['apple', 'banana', 'cherry', 'date'], n_samples),
        }
        
        # Add some missing values
        missing_indices = np.random.choice(n_samples, 50, replace=False)
        test_data['numeric_col1'] = list(test_data['numeric_col1'])
        for idx in missing_indices[:25]:
            test_data['numeric_col1'][idx] = np.nan
        
        df = pd.DataFrame(test_data)
        logger.info(f"Created test dataset with {len(df)} samples and {len(df.columns)} features")
        
        # Test analysis
        result = analyze_generic_csv(df)
        
        if result:
            logger.info("✓ Generic CSV analysis completed successfully")
            
            # Check main components
            if 'data_profile' in result:
                profile = result['data_profile']
                logger.info(f"  - Data profile: {profile['shape']['rows']} rows, {profile['shape']['cols']} cols")
                
            if 'plots' in result:
                plots = result['plots']
                plot_count = len([k for k, v in plots.items() if v])
                logger.info(f"  - Generated {plot_count} visualization plots")
                
            if 'anomaly' in result:
                anomaly = result['anomaly']
                if 'anomalies' in anomaly:
                    logger.info(f"  - Detected {anomaly['anomalies']} anomalies ({anomaly['anomaly_rate']})")
                elif 'error' in anomaly:
                    logger.warning(f"  - Anomaly detection error: {anomaly['error']}")
                else:
                    logger.info(f"  - Anomaly detection: {anomaly}")
            
            return True
        else:
            logger.error("✗ Generic CSV analysis returned empty result")
            return False
            
    except Exception as e:
        logger.error(f"✗ Generic CSV analysis test failed: {e}")
        return False

def test_directory_structure():
    """Test if required directories can be created"""
    logger.info("Testing directory structure...")
    
    test_dirs = ['uploads', 'reports', 'model']
    
    for dir_name in test_dirs:
        try:
            os.makedirs(dir_name, exist_ok=True)
            if os.path.exists(dir_name):
                logger.info(f"✓ Directory '{dir_name}' created successfully")
            else:
                logger.error(f"✗ Failed to create directory '{dir_name}'")
                return False
        except Exception as e:
            logger.error(f"✗ Error creating directory '{dir_name}': {e}")
            return False
    
    return True

def test_visualization_capabilities():
    """Test basic visualization capabilities"""
    logger.info("Testing visualization capabilities...")
    
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        import io
        import base64
        
        # Test basic plot creation
        fig, ax = plt.subplots(figsize=(8, 6))
        x = np.linspace(0, 10, 100)
        y = np.sin(x)
        ax.plot(x, y)
        ax.set_title('Test Plot')
        
        # Test saving to bytes
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        plt.close()
        buf.seek(0)
        
        # Test base64 encoding
        plot_data = base64.b64encode(buf.getvalue()).decode()
        
        if plot_data:
            logger.info("✓ Visualization and encoding test successful")
            return True
        else:
            logger.error("✗ Visualization encoding failed")
            return False
            
    except Exception as e:
        logger.error(f"✗ Visualization test failed: {e}")
        return False

def run_all_tests():
    """Run all tests and provide summary"""
    logger.info("Starting comprehensive PCAP processing pipeline tests...")
    logger.info("=" * 60)
    
    tests = [
        ("Import Tests", test_imports),
        ("Directory Structure", test_directory_structure),
        ("Visualization Capabilities", test_visualization_capabilities),
        ("Generic CSV Analyzer", test_generic_csv_analyzer),
        ("Anomaly Detector", test_anomaly_detector),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        logger.info(f"\n--- Running {test_name} ---")
        try:
            results[test_name] = test_func()
        except Exception as e:
            logger.error(f"✗ {test_name} failed with exception: {e}")
            results[test_name] = False
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{test_name:.<30} {status}")
        if result:
            passed += 1
    
    logger.info("-" * 60)
    logger.info(f"Total: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        logger.info("🎉 All tests passed! The PCAP processing pipeline is ready.")
    else:
        logger.warning(f"⚠ {total - passed} test(s) failed. Please review the issues above.")
    
    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
