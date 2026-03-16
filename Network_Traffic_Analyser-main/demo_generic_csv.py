#!/usr/bin/env python3
"""
Demo script showing the generic CSV analysis capability.
This script creates sample CSV files with different schemas and analyzes them.
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta
from app import analyze_generic_csv

def create_sample_csvs():
    """Create various sample CSV files with different schemas to demonstrate generic analysis."""
    
    # Sample 1: E-commerce data
    print("Creating sample e-commerce dataset...")
    np.random.seed(42)
    n_samples = 1000
    
    ecommerce_data = {
        'customer_id': np.arange(1, n_samples + 1),
        'age': np.random.normal(35, 12, n_samples).astype(int),
        'gender': np.random.choice(['M', 'F', 'Other'], n_samples, p=[0.45, 0.45, 0.1]),
        'city': np.random.choice(['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix', 'Philadelphia'], n_samples),
        'purchase_amount': np.random.lognormal(4, 1, n_samples),
        'items_bought': np.random.poisson(2, n_samples) + 1,
        'customer_satisfaction': np.random.choice([1, 2, 3, 4, 5], n_samples, p=[0.05, 0.1, 0.2, 0.35, 0.3]),
        'purchase_date': pd.date_range('2023-01-01', periods=n_samples, freq='1H'),
        'payment_method': np.random.choice(['Credit Card', 'PayPal', 'Bank Transfer', 'Cash'], n_samples),
        'product_category': np.random.choice(['Electronics', 'Clothing', 'Home & Garden', 'Books', 'Sports'], n_samples),
        'is_member': np.random.choice([True, False], n_samples, p=[0.6, 0.4])
    }
    
    df_ecommerce = pd.DataFrame(ecommerce_data)
    # Introduce some missing values
    df_ecommerce.loc[np.random.choice(n_samples, 50, replace=False), 'customer_satisfaction'] = np.nan
    df_ecommerce.loc[np.random.choice(n_samples, 30, replace=False), 'city'] = np.nan
    
    df_ecommerce.to_csv('sample_ecommerce.csv', index=False)
    
    # Sample 2: Medical/Health data
    print("Creating sample medical dataset...")
    medical_data = {
        'patient_id': np.arange(1, n_samples + 1),
        'age': np.random.normal(50, 20, n_samples).clip(0, 100).astype(int),
        'bmi': np.random.normal(25, 5, n_samples).clip(15, 50),
        'blood_pressure_systolic': np.random.normal(130, 20, n_samples).clip(80, 200).astype(int),
        'blood_pressure_diastolic': np.random.normal(85, 15, n_samples).clip(50, 130).astype(int),
        'cholesterol': np.random.normal(200, 40, n_samples).clip(100, 400),
        'heart_rate': np.random.normal(75, 15, n_samples).clip(40, 150).astype(int),
        'smoker': np.random.choice(['Yes', 'No'], n_samples, p=[0.3, 0.7]),
        'exercise_hours_per_week': np.random.exponential(3, n_samples).clip(0, 20),
        'diagnosis': np.random.choice(['Healthy', 'Pre-diabetic', 'Diabetic', 'Hypertensive', 'Heart Disease'], 
                                    n_samples, p=[0.4, 0.2, 0.15, 0.15, 0.1]),
        'treatment_cost': np.random.lognormal(6, 1.5, n_samples),
        'insurance_coverage': np.random.uniform(0, 1, n_samples),
    }
    
    df_medical = pd.DataFrame(medical_data)
    # Introduce missing values
    df_medical.loc[np.random.choice(n_samples, 100, replace=False), 'exercise_hours_per_week'] = np.nan
    df_medical.loc[np.random.choice(n_samples, 80, replace=False), 'cholesterol'] = np.nan
    
    df_medical.to_csv('sample_medical.csv', index=False)
    
    # Sample 3: Financial/Stock data
    print("Creating sample financial dataset...")
    dates = pd.date_range('2020-01-01', '2023-12-31', freq='D')
    n_dates = len(dates)
    
    # Simulate stock prices with random walk
    initial_price = 100
    returns = np.random.normal(0.0005, 0.02, n_dates)  # Small daily returns with volatility
    prices = [initial_price]
    for ret in returns[1:]:
        prices.append(prices[-1] * (1 + ret))
    
    financial_data = {
        'date': dates,
        'open_price': prices,
        'high_price': [p * (1 + abs(np.random.normal(0, 0.01))) for p in prices],
        'low_price': [p * (1 - abs(np.random.normal(0, 0.01))) for p in prices],
        'close_price': [p + np.random.normal(0, 1) for p in prices],
        'volume': np.random.lognormal(12, 1, n_dates).astype(int),
        'market_cap': [p * np.random.lognormal(15, 0.5) for p in prices],
        'pe_ratio': np.random.lognormal(3, 0.5, n_dates),
        'dividend_yield': np.random.exponential(0.03, n_dates),
        'sector': np.random.choice(['Technology', 'Healthcare', 'Finance', 'Energy', 'Consumer'], n_dates),
        'earnings_surprise': np.random.normal(0, 0.1, n_dates)
    }
    
    df_financial = pd.DataFrame(financial_data)
    # Introduce missing values
    df_financial.loc[np.random.choice(n_dates, 200, replace=False), 'dividend_yield'] = np.nan
    df_financial.loc[np.random.choice(n_dates, 150, replace=False), 'earnings_surprise'] = np.nan
    
    df_financial.to_csv('sample_financial.csv', index=False)
    
    print(f"Created 3 sample CSV files with different schemas:")
    print(f"1. sample_ecommerce.csv - {df_ecommerce.shape[0]} rows, {df_ecommerce.shape[1]} columns")
    print(f"2. sample_medical.csv - {df_medical.shape[0]} rows, {df_medical.shape[1]} columns")
    print(f"3. sample_financial.csv - {df_financial.shape[0]} rows, {df_financial.shape[1]} columns")
    
    return ['sample_ecommerce.csv', 'sample_medical.csv', 'sample_financial.csv']


def analyze_sample_files(csv_files):
    """Analyze each sample CSV file using the generic analysis pipeline."""
    
    for csv_file in csv_files:
        print(f"\n{'='*60}")
        print(f"ANALYZING: {csv_file}")
        print('='*60)
        
        try:
            # Load the CSV
            df = pd.read_csv(csv_file)
            print(f"Loaded CSV with shape: {df.shape}")
            print(f"Columns: {list(df.columns)}")
            print(f"Data types: {df.dtypes.value_counts().to_dict()}")
            
            # Run generic analysis
            result = analyze_generic_csv(df)
            
            # Display results
            print(f"\nANALYSIS RESULTS:")
            print("-" * 40)
            
            # Data profile
            profile = result['data_profile']
            print(f"Shape: {profile.get('shape', 'N/A')}")
            print(f"Memory usage: {profile.get('memory_mb', 0):.1f} MB")
            
            missing_vals = profile.get('missing', {})
            total_missing = sum(missing_vals.values())
            print(f"Total missing values: {total_missing}")
            if total_missing > 0:
                print(f"Columns with missing values: {[(k, v) for k, v in missing_vals.items() if v > 0]}")
            
            # Anomaly detection
            anomaly = result['anomaly']
            if 'anomalies' in anomaly:
                print(f"Anomaly detection: {anomaly['anomalies']} anomalies ({anomaly['anomaly_rate']})")
            else:
                print(f"Anomaly detection: {anomaly}")
            
            # Plots generated
            plots = result['plots']
            print(f"Generated plots: {list(plots.keys())}")
            
            # Derived metrics
            numeric_sums = result['derived'].get('numeric_sums', {})
            if numeric_sums:
                print(f"Numeric column sums: {len(numeric_sums)} columns")
                # Show top 3 by sum
                sorted_sums = sorted(numeric_sums.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
                print(f"Top numeric columns by sum: {sorted_sums}")
            
        except Exception as e:
            print(f"ERROR analyzing {csv_file}: {str(e)}")
            import traceback
            traceback.print_exc()


def main():
    """Main demonstration function."""
    print("Generic CSV Analysis Demonstration")
    print("=" * 50)
    print("This demo shows how the system can analyze ANY CSV file structure.")
    print("It automatically:")
    print("- Profiles the data (shape, types, missing values, summary stats)")
    print("- Runs unsupervised anomaly detection")
    print("- Generates appropriate visualizations")
    print("- Provides actionable insights")
    print()
    
    # Create sample files
    csv_files = create_sample_csvs()
    
    # Analyze each file
    analyze_sample_files(csv_files)
    
    print(f"\n{'='*60}")
    print("DEMONSTRATION COMPLETE")
    print('='*60)
    print("The system successfully analyzed 3 completely different CSV schemas:")
    print("1. E-commerce data (customers, purchases, satisfaction)")
    print("2. Medical data (patients, health metrics, diagnoses)")
    print("3. Financial data (stock prices, volumes, ratios)")
    print()
    print("Each analysis was automatic and schema-agnostic!")
    print("Now you can upload ANY CSV file to the web interface and get similar analysis.")
    print()
    print("To run the web interface:")
    print("python app.py")
    print("Then open http://localhost:5000 and upload any CSV file!")
    
    # Clean up sample files
    try:
        for csv_file in csv_files:
            os.remove(csv_file)
        print(f"\nCleaned up sample files.")
    except Exception as e:
        print(f"Warning: Could not clean up sample files: {e}")


if __name__ == "__main__":
    main()
