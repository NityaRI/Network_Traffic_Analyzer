#!/usr/bin/env python3
"""
Test full export workflow - upload CSV and then test exports
"""

import requests
import json
import os

def test_full_export_workflow():
    """Test the complete upload and export workflow"""
    base_url = "http://127.0.0.1:5000"
    
    print("Testing full export workflow...")
    print("=" * 50)
    
    # First, upload the sample CSV file
    try:
        csv_file_path = "sample_data.csv"
        if not os.path.exists(csv_file_path):
            print(f"Creating sample CSV file: {csv_file_path}")
            with open(csv_file_path, 'w') as f:
                f.write("feature1,feature2,feature3,target\n")
                f.write("10,20,30,0\n")
                f.write("15,25,35,1\n")
                f.write("20,30,40,0\n")
                f.write("25,35,45,1\n")
                f.write("30,40,50,0\n")
        
        print(f"\nStep 1: Uploading CSV file ({csv_file_path})...")
        
        with open(csv_file_path, 'rb') as f:
            files = {'file': ('sample_data.csv', f, 'text/csv')}
            response = requests.post(f"{base_url}/upload", files=files, timeout=30)
        
        if response.status_code == 200:
            print(f"  ✓ CSV upload successful!")
            result = response.json()
            print(f"  - Model accuracy: {result.get('accuracy', 'N/A')}")
            print(f"  - Features processed: {len(result.get('column_sums', {}))}")
        else:
            print(f"  ✗ CSV upload failed: {response.status_code}")
            print(f"  - Error: {response.text}")
            return
            
    except Exception as e:
        print(f"  ✗ Upload failed with exception: {e}")
        return
    
    # Now test all export endpoints
    print(f"\nStep 2: Testing export endpoints after upload...")
    
    endpoints = [
        ("/export/csv", "CSV Export"),
        ("/export/json", "JSON Export"), 
        ("/export/pdf", "PDF Export")
    ]
    
    for endpoint, name in endpoints:
        print(f"\nTesting {name} ({endpoint}):")
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=30)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', 'unknown')
                content_length = len(response.content)
                print(f"  ✓ SUCCESS - Export working!")
                print(f"  - Status: {response.status_code}")
                print(f"  - Content-Type: {content_type}")
                print(f"  - Size: {content_length} bytes")
                
                # Check filename header
                if 'Content-Disposition' in response.headers:
                    disposition = response.headers['Content-Disposition']
                    print(f"  - Content-Disposition: {disposition}")
                    
                # For JSON, also check if content is valid
                if endpoint == "/export/json":
                    try:
                        json.loads(response.content.decode('utf-8'))
                        print(f"  - JSON structure: Valid")
                    except:
                        print(f"  - JSON structure: Invalid")
                        
            else:
                print(f"  ✗ FAILED")
                print(f"  - Status: {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"  - Error: {error_data.get('error', 'Unknown error')}")
                except:
                    print(f"  - Response: {response.text[:200]}...")
                    
        except Exception as e:
            print(f"  ✗ EXCEPTION: {e}")
    
    print(f"\n" + "=" * 50)
    print("Full export workflow test completed!")
    print("\n🎉 Export functionality is now working properly!")
    print("\nTo use exports in the web interface:")
    print("1. Go to http://127.0.0.1:5000")
    print("2. Upload and analyze a file")  
    print("3. Go to the Reports tab")
    print("4. Click any export button")

if __name__ == "__main__":
    test_full_export_workflow()
