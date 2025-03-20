#!/usr/bin/env python3
"""
Prefix Validator - Main Integration Script

This script combines IP prefix extraction and validation into a single workflow.
Uses the RIPE NCC RPKI validator API for prefix validation.
"""

import os
import sys
import argparse
import csv
import tempfile
from src.ip_extractor import extract_ips
from src.ip_validator import validate_ip_addresses

def process_file(input_file, asn, output_dir=None, batch_size=10, delay=1.0):
    """
    Process a file containing IP prefixes: extract and validate them.
    
    Args:
        input_file (str): Path to input file containing IP prefixes
        asn (int): Autonomous System Number for validation
        output_dir (str, optional): Directory to save output files
        batch_size (int): Number of IPs to process before pause
        delay (float): Delay in seconds between batches
        
    Returns:
        bool: Success flag
    """
    if not os.path.exists(input_file):
        print(f"Error: Input file {input_file} not found.")
        return False
    
    # Set up output directory
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = os.path.dirname(os.path.abspath(input_file))
    
    # Generate output file names
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    extraction_output = os.path.join(output_dir, f"{base_name}_extracted_prefixes.csv")
    validation_output = os.path.join(output_dir, f"{base_name}_validated_prefixes.csv")
    combined_output = os.path.join(output_dir, f"{base_name}_combined_results.csv")
    
    # Step 1: Extract IP prefixes
    print(f"\n{'='*70}")
    print(f"STEP 1: EXTRACTING IP PREFIXES FROM {input_file}")
    print(f"{'='*70}")
    
    data, headers, success = extract_ips(input_file, extraction_output)
    
    if not success or not data:
        print("Error: No IP prefixes found in the input file.")
        return False
    
    print(f"Successfully extracted {len(data)} IP prefixes from {input_file}")
    print(f"Extraction results saved to {extraction_output}")
    
    # Step 2: Validate the extracted IP prefixes
    print(f"\n{'='*70}")
    print(f"STEP 2: VALIDATING {len(data)} IP PREFIXES WITH ASN {asn}")
    print(f"{'='*70}")
    
    # Collect all IP prefixes from the extracted data
    prefixes = [item['IP_Address'] for item in data if 'IP_Address' in item]
    
    # Validate the prefixes using the RPKI API
    validation_results = validate_ip_addresses(
        prefixes, 
        asn,
        validation_output,
        batch_size,
        delay
    )
    
    if not validation_results:
        print("Error: Failed to validate IP prefixes.")
        return False
    
    # Step 3: Create a combined results file
    print(f"\n{'='*70}")
    print(f"STEP 3: COMBINING EXTRACTION AND VALIDATION RESULTS")
    print(f"{'='*70}")
    
    # Create a lookup dict for validation results
    validation_dict = {result['IP_Address']: result for result in validation_results}
    
    try:
        with open(combined_output, 'w', newline='') as csvfile:
            # Combine all possible headers from both extraction and validation
            extraction_headers = set(headers)
            validation_headers = set()
            for result in validation_results:
                validation_headers.update(result.keys())
            
            # Remove duplicate IP_Address field
            if 'IP_Address' in validation_headers:
                validation_headers.remove('IP_Address')
            
            # Create combined headers with IP_Address first
            combined_headers = ['IP_Address'] + [
                h for h in sorted(list(extraction_headers | validation_headers)) 
                if h != 'IP_Address'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=combined_headers)
            writer.writeheader()
            
            for item in data:
                if 'IP_Address' in item:
                    ip = item['IP_Address']
                    # Get validation result for this IP
                    validation_result = validation_dict.get(ip, {})
                    
                    # Merge extraction and validation data
                    combined_row = item.copy()
                    for k, v in validation_result.items():
                        if k != 'IP_Address':  # Skip duplicate IP_Address field
                            combined_row[k] = v
                    
                    writer.writerow(combined_row)
        
        print(f"Combined results saved to {combined_output}")
        
        print(f"\n{'='*70}")
        print(f"PROCESS COMPLETED SUCCESSFULLY")
        print(f"{'='*70}")
        print(f"Extraction results: {extraction_output}")
        print(f"Validation results: {validation_output}")
        print(f"Combined results: {combined_output}")
        
        return True
    
    except Exception as e:
        print(f"Error creating combined results: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Extract and validate IP prefixes from various file formats using RPKI API.'
    )
    parser.add_argument('input_file', help='Path to the input file containing IP prefixes')
    parser.add_argument('--asn', type=int, required=True,
                        help='Autonomous System Number for validation')
    parser.add_argument('-o', '--output-dir', 
                        help='Directory to save output files')
    parser.add_argument('--batch-size', type=int, default=10,
                        help='Number of IPs to process before pause (default: 10)')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay in seconds between batches (default: 1.0)')
    
    args = parser.parse_args()
    
    success = process_file(
        args.input_file,
        args.asn,
        args.output_dir,
        args.batch_size,
        args.delay
    )
    
    if not success:
        print("Process failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()