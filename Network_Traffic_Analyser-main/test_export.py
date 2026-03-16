#!/usr/bin/env python3
"""
Test script for export functionality
Tests the export endpoints to ensure they work correctly
"""

import requests
import json

def test_export_endpoints():
    """Test all export endpoints"""
    base_url = "http://127.0.0.1:5000"
    
    print("Testing export endpoints...")
    print("=" * 50)
    
    # Test endpoints
    endpoints = [
        ("/export/csv", "CSV Export"),
        ("/export/json", "JSON Export"),
        ("/export/pdf", "PDF Export")
    ]
    
    for endpoint, name in endpoints:
        print(f"\nTesting {name} ({endpoint}):")
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=10)
            
            if response.status_code == 200:
                # Success - check content type and size
                content_type = response.headers.get('Content-Type', 'unknown')
                content_length = len(response.content)
                print(f"  ✓ SUCCESS")
                print(f"  - Status: {response.status_code}")
                print(f"  - Content-Type: {content_type}")
                print(f"  - Size: {content_length} bytes")
                
                # Check for proper filename in header
                if 'Content-Disposition' in response.headers:
                    disposition = response.headers['Content-Disposition']
                    print(f"  - Content-Disposition: {disposition}")
                
            elif response.status_code == 400:
                # Expected error when no data is available
                try:
                    error_data = response.json()
                    print(f"  ✓ EXPECTED ERROR (no data uploaded yet)")
                    print(f"  - Status: {response.status_code}")
                    print(f"  - Error: {error_data.get('error', 'Unknown error')}")
                except:
                    print(f"  ⚠ ERROR - Unable to parse error response")
            else:
                print(f"  ✗ FAILED")
                print(f"  - Status: {response.status_code}")
                print(f"  - Response: {response.text[:200]}...")
                
        except requests.exceptions.RequestException as e:
            print(f"  ✗ CONNECTION FAILED: {e}")
        except Exception as e:
            print(f"  ✗ UNEXPECTED ERROR: {e}")
    
    print("\n" + "=" * 50)
    print("Export endpoint tests completed!")
    print("\nTo fully test exports:")
    print("1. Go to http://127.0.0.1:5000")
    print("2. Upload a CSV file or PCAP file")
    print("3. Analyze the data")
    print("4. Go to the Reports tab")
    print("5. Click the export buttons")

if __name__ == "__main__":
    test_export_endpoints()
