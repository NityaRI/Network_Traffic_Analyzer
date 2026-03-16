#!/usr/bin/env python3
"""
Network Traffic Analysis System - Startup Script
Automatically installs dependencies and starts the application
"""

import subprocess
import sys
import os
import time

def install_requirements():
    """Install required packages"""
    print("Installing required packages...")
    
    packages = [
        "flask", "flask-cors", "pandas", "numpy", "scikit-learn", 
        "matplotlib", "seaborn", "plotly", "joblib", "reportlab", 
        "weasyprint", "Pillow", "psutil", "werkzeug", "lxml"
    ]
    
    # Try to install scapy and pyshark (optional)
    optional_packages = ["scapy", "pyshark", "networkx", "folium", "tensorflow"]
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✓ {package} installed successfully")
        except subprocess.CalledProcessError:
            print(f"✗ Failed to install {package}")
    
    print("\nInstalling optional packages (may fail on some systems):")
    for package in optional_packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✓ {package} installed successfully")
        except subprocess.CalledProcessError:
            print(f"⚠ {package} installation failed (optional)")

def create_directories():
    """Create necessary directories"""
    dirs = ["uploads", "reports", "model"]
    for dir_name in dirs:
        os.makedirs(dir_name, exist_ok=True)
        print(f"✓ Created directory: {dir_name}")

def start_application():
    """Start the Flask application"""
    print("\n" + "="*50)
    print("NETWORK TRAFFIC ANALYSIS SYSTEM")
    print("="*50)
    print("Starting the application...")
    print("Access the web interface at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print("="*50 + "\n")
    
    try:
        from app import app
        app.run(debug=False, host='0.0.0.0', port=5000)
    except ImportError as e:
        print(f"Error importing app: {e}")
        print("Please ensure app.py exists in the current directory")
    except KeyboardInterrupt:
        print("\nShutting down the server...")
    except Exception as e:
        print(f"Error starting application: {e}")

if __name__ == "__main__":
    print("Network Traffic Analysis System - Setup")
    print("=" * 40)
    
    # Install requirements
    install_requirements()
    
    # Create directories
    print("\nCreating necessary directories...")
    create_directories()
    
    # Wait a moment
    time.sleep(2)
    
    # Start application
    start_application()
