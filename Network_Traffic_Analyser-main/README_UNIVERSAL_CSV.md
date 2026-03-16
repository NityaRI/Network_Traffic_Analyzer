# Universal CSV Analysis System

## Overview

This system has been enhanced to analyze **ANY CSV file** with **ANY schema**, not just network-specific data. It automatically detects the data structure and provides comprehensive analysis regardless of the domain.

## 🎯 Universal Analysis Capabilities

### **Automatic Schema Detection**
- **No predefined schema required** - works with any CSV structure
- **Dynamic column type detection** (numeric, categorical, datetime, boolean)
- **Intelligent data profiling** regardless of domain

### **Comprehensive Analysis Pipeline**

#### 1. **Data Profiling**
- Dataset shape (rows × columns)
- Memory usage calculation
- Data type distribution
- Missing value analysis
- Statistical summaries for all columns

#### 2. **Unsupervised Anomaly Detection**
- **IsolationForest** algorithm for outlier detection
- Automatic preprocessing for mixed data types
- Categorical encoding with cardinality control
- Anomaly rate calculation and reporting

#### 3. **Intelligent Visualizations**
- **Missing Value Analysis**: Bar chart of missing values per column
- **Correlation Heatmap**: For numeric columns
- **Distribution Plots**: For top numeric columns by variance
- **Category Frequency**: For categorical columns
- **Feature Importance**: Via surrogate model on anomaly labels

#### 4. **Adaptive Processing**
- **DateTime conversion** to numeric timestamps
- **One-hot encoding** for categoricals (with cardinality limits)
- **Outlier-robust scaling** for mixed data types
- **Memory-efficient** batch processing for large files

## 📊 Example Use Cases

### E-commerce Data
```csv
customer_id,age,gender,city,purchase_amount,items_bought,satisfaction
1,35,M,New York,157.32,3,4
2,42,F,Los Angeles,89.45,1,5
...
```
**Analysis Provides:**
- Customer behavior anomalies
- Purchase pattern analysis  
- Geographic distribution insights
- Customer satisfaction correlations

### Medical/Health Data
```csv
patient_id,age,bmi,blood_pressure,cholesterol,diagnosis,treatment_cost
101,45,23.1,120/80,180,Healthy,250.00
102,67,29.8,140/90,240,Hypertensive,1200.50
...
```
**Analysis Provides:**
- Patient outlier detection
- Health metric correlations
- Treatment cost anomalies
- Risk factor identification

### Financial Data
```csv
date,open_price,close_price,volume,market_cap,pe_ratio,sector
2023-01-01,100.50,102.30,1000000,5000000000,15.2,Technology
2023-01-02,102.30,99.80,1200000,4990000000,15.1,Technology
...
```
**Analysis Provides:**
- Price movement anomalies
- Volume spike detection
- Sector performance analysis
- Valuation ratio insights

### Survey/Research Data
```csv
respondent_id,age_group,education,income_range,satisfaction_score,response_time
1001,25-34,Bachelor,50-75k,7,45
1002,35-44,Master,75-100k,8,62
...
```
**Analysis Provides:**
- Response quality anomalies
- Demographic pattern analysis
- Satisfaction driver identification
- Survey completion insights

## 🚀 Usage

### Web Interface
1. **Start the application:**
   ```bash
   python app.py
   ```

2. **Open your browser:** `http://localhost:5000`

3. **Upload ANY CSV file:**
   - Select "CSV Data" option
   - Drag & drop or browse for your CSV file
   - Click "Start Analysis"

4. **View Results:**
   - Automatic data profiling
   - Interactive visualizations
   - Anomaly detection results
   - Comprehensive insights

### Command Line Demo
```bash
python demo_generic_csv.py
```
This creates sample datasets from different domains and demonstrates the analysis capabilities.

### Programmatic Usage
```python
from app import analyze_generic_csv
import pandas as pd

# Load any CSV file
df = pd.read_csv('your_data.csv')

# Run generic analysis
result = analyze_generic_csv(df)

# Access results
profile = result['data_profile']
anomalies = result['anomaly']
plots = result['plots']  # Base64 encoded images
```

## 📋 Analysis Output

### Data Profile
```json
{
  "shape": {"rows": 1000, "cols": 12},
  "memory_mb": 0.5,
  "dtypes": {"float64": 6, "object": 4, "int64": 2},
  "missing": {"column1": 0, "column2": 15, "column3": 0},
  "describe_html": "<table>...</table>"
}
```

### Anomaly Detection
```json
{
  "model": "IsolationForest",
  "anomalies": 47,
  "anomaly_rate": "4.70%"
}
```

### Generated Visualizations
- `missing_bar`: Missing values per column
- `correlation_heatmap`: Numeric correlations
- `numeric_distributions`: Top variable distributions
- `categorical_topfreq`: Category frequencies
- `feature_importance`: Anomaly-driving features

## ⚡ Key Features

### **Schema-Agnostic**
- Works with **any column names**
- Handles **mixed data types** automatically
- **No configuration required**

### **Robust Processing** 
- Handles **missing values** gracefully
- **Memory efficient** for large files
- **Error tolerant** with fallback options

### **Rich Insights**
- **Statistical profiling** of all columns
- **Anomaly detection** without labels
- **Visual analysis** adapted to data types
- **Feature importance** for anomalies

### **Production Ready**
- **Web interface** for easy use
- **RESTful API** for integration
- **Batch processing** support
- **Export capabilities**

## 🎨 Web Interface Features

- **Modern responsive design** with glassmorphism effects
- **Drag & drop file upload**
- **Real-time analysis progress**
- **Interactive dashboards**
- **Dynamic chart generation**
- **Detailed data profiling**
- **Export functionality**

## 🔧 Technical Implementation

### Backend (Flask)
- `analyze_generic_csv()`: Core analysis pipeline
- Automatic data type detection
- Robust preprocessing pipeline
- Multiple visualization generators
- Error handling & logging

### Frontend (HTML/JS/Bootstrap)
- Responsive dashboard design
- Chart.js integration
- Progress indicators
- Results display system
- Profile metrics cards

### Machine Learning
- Scikit-learn IsolationForest
- Automatic feature encoding
- Surrogate model importance
- Ensemble ready architecture

## 🚀 Getting Started

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application:**
   ```bash
   python app.py
   ```

3. **Upload Any CSV:**
   - Open `http://localhost:5000`
   - Select any CSV file
   - Get instant comprehensive analysis!

## ✨ What Makes This Special

This system represents a **universal data analysis solution** that:

- **Requires zero configuration** - just upload and analyze
- **Works across all domains** - business, scientific, financial, social
- **Provides professional insights** - statistical profiling, anomaly detection, visualizations
- **Scales efficiently** - handles small datasets to large files
- **Offers multiple interfaces** - web UI, API, command line

Whether you're analyzing customer data, scientific measurements, financial records, survey responses, or any other tabular data, this system automatically adapts and provides meaningful insights.

**No more domain-specific tools needed - one system for all your CSV analysis needs!**
