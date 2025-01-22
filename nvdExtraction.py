import json
import csv
import zipfile
import os

def extract_cvss_scores(impact_json):
    """Extract all possible CVSS scores from impact JSON."""
    scores = {
        'CVSS:2.0.baseScore': 'NONE',
        'CVSS:2.0.exploitabilityScore': 'NONE',
        'CVSS:3.0.baseScore': 'NONE',
        'CVSS:3.0.exploitabilityScore': 'NONE',
        'CVSS:3.1.baseScore': 'NONE',
        'CVSS:3.1.exploitabilityScore': 'NONE',
        'CVSS:4.0.baseScore': 'NONE',
        'CVSS:4.0.exploitabilityScore': 'NONE'
    }
    
    if not impact_json:
        return scores

    try:
        # CVSS 2.0
        if 'baseMetricV2' in impact_json:
            base_metric_v2 = impact_json['baseMetricV2']
            if 'cvssV2' in base_metric_v2:
                scores['CVSS:2.0.baseScore'] = base_metric_v2['cvssV2'].get('baseScore', 'NONE')
                scores['CVSS:2.0.exploitabilityScore'] = base_metric_v2.get('exploitabilityScore', 'NONE')

        # CVSS 3.x (both 3.0 and 3.1)
        if 'baseMetricV3' in impact_json:
            base_metric_v3 = impact_json['baseMetricV3']
            if 'cvssV3' in base_metric_v3:
                version = base_metric_v3['cvssV3'].get('version', '')
                if version.startswith('3.0'):
                    scores['CVSS:3.0.baseScore'] = base_metric_v3['cvssV3'].get('baseScore', 'NONE')
                    scores['CVSS:3.0.exploitabilityScore'] = base_metric_v3.get('exploitabilityScore', 'NONE')
                elif version.startswith('3.1'):
                    scores['CVSS:3.1.baseScore'] = base_metric_v3['cvssV3'].get('baseScore', 'NONE')
                    scores['CVSS:3.1.exploitabilityScore'] = base_metric_v3.get('exploitabilityScore', 'NONE')

        # CVSS 4.0
        if 'baseMetricV4' in impact_json:
            base_metric_v4 = impact_json['baseMetricV4']
            if 'cvssV4' in base_metric_v4:
                scores['CVSS:4.0.baseScore'] = base_metric_v4['cvssV4'].get('baseScore', 'NONE')
                scores['CVSS:4.0.exploitabilityScore'] = base_metric_v4.get('exploitabilityScore', 'NONE')
    
    except Exception as e:
        print(f"Error extracting CVSS scores: {str(e)}")
    
    return scores

def process_nvd_file(json_content):
    """Process NVD JSON content and extract required fields."""
    try:
        data = json.loads(json_content)
        results = []
        
        for cve_item in data.get('CVE_Items', []):
            try:
                result = {}
                
                # 1. CVE ID
                cve_data = cve_item.get('cve', {})
                cve_meta = cve_data.get('CVE_data_meta', {})
                result['CVE ID'] = cve_meta.get('ID', '')
                
                # 2. Description (English)
                desc_data = cve_data.get('description', {}).get('description_data', [])
                result['Description'] = next((desc.get('value', '') for desc in desc_data 
                                          if desc.get('lang') == 'en'), '')
                
                # 3. Impact (full JSON structure)
                impact = cve_item.get('impact')
                result['Impact'] = json.dumps(impact) if impact else ''
                
                # 4. Published Date
                result['Published Date'] = cve_item.get('publishedDate', '')
                
                # 5. Associated CWE
                problemtype_data = cve_data.get('problemtype', {}).get('problemtype_data', [])
                if problemtype_data:
                    descriptions = problemtype_data[0].get('description', [])
                    result['CWE'] = next((desc.get('value', '') for desc in descriptions 
                                        if desc.get('lang') == 'en'), '')
                else:
                    result['CWE'] = ''
                
                # 6. Extract all CVSS scores
                if impact:
                    impact_data = json.loads(impact) if isinstance(impact, str) else impact
                    cvss_scores = extract_cvss_scores(impact_data)
                else:
                    cvss_scores = extract_cvss_scores({})
                result.update(cvss_scores)
                
                results.append(result)
                
            except Exception as e:
                print(f"Error processing CVE item: {str(e)}")
                continue
            
        return results
        
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {str(e)}")
        return []
    except Exception as e:
        print(f"Error processing NVD data: {str(e)}")
        return []

def process_single_feed(zip_path, output_csv):
    """Process a single NVD feed ZIP file and create a CSV file."""
    try:
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            json_filename = next(name for name in zip_ref.namelist() if name.endswith('.json'))
            print(f"Reading JSON file: {json_filename}")
            
            with zip_ref.open(json_filename) as json_file:
                json_content = json_file.read().decode('utf-8')
                results = process_nvd_file(json_content)
                
                if not results:
                    print("No data found in file")
                    return
                
                # Write to CSV
                with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                    headers = ['CVE ID', 'Description', 'Impact', 'Published Date', 'CWE',
                             'CVSS:2.0.baseScore', 'CVSS:2.0.exploitabilityScore',
                             'CVSS:3.0.baseScore', 'CVSS:3.0.exploitabilityScore',
                             'CVSS:3.1.baseScore', 'CVSS:3.1.exploitabilityScore',
                             'CVSS:4.0.baseScore', 'CVSS:4.0.exploitabilityScore']
                    writer = csv.DictWriter(csvfile, fieldnames=headers)
                    writer.writeheader()
                    writer.writerows(results)
                    
                print(f"\nCSV file created: {output_csv}")
                print("Headers:", headers)
    
    except Exception as e:
        print(f"Error processing file: {str(e)}")

def main():
    # input_zip = os.path.join('cve_data', 'nvdcve-1.1-2025.json.zip')
    # output_csv = os.path.join('output', 'nvd_data_2025.csv')
    
    # print(f"Starting to process NVD feed: {input_zip}")
    # process_single_feed(input_zip, output_csv)
    # print("Processing complete.")

    # Use glob to find all matching zip files
    import glob
    zip_files = glob.glob(os.path.join('cve_data', 'nvdcve-1.1-*.json.zip'))
    
    print(f"Found {len(zip_files)} NVD feed files to process")
    
    # Process each zip file
    for zip_path in zip_files:
        # Extract year from filename for output CSV
        print("*************** ",os.path.basename(zip_path).split('-'))
        year = os.path.basename(zip_path).split('-')[2].split('.')[0]
        
        output_csv = os.path.join('output', f'nvd_data_{year}.csv')
        
        print(f"\nProcessing: {zip_path}")
        process_single_feed(zip_path, output_csv)
    
    print("\nAll processing complete.")    

if __name__ == "__main__":
    main()
